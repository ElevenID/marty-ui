// Windows SDK COM interfaces supply the ABI; no hand-declared vtables.
#include <windows.h>
#include <UIAutomation.h>
#include <wrl/client.h>
#include <algorithm>
#include <cwctype>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
using Microsoft::WRL::ComPtr;
static_assert(UIA_IsDialogPropertyId == 30174 && UIA_AriaRolePropertyId == 30101);
static_assert(UIA_ProcessIdPropertyId == 30002 && UIA_ControlTypePropertyId == 30003);
static_assert(UIA_DocumentControlTypeId == 50030 && UIA_ButtonControlTypeId == 50000);
static void check(HRESULT hr) { if (FAILED(hr)) throw std::runtime_error("Native UIA operation failed"); }
struct Value { VARIANT v; Value(){VariantInit(&v);} ~Value(){VariantClear(&v);} };
static bool dialogBoolean(const VARIANT& v) { return v.vt==VT_BOOL && v.boolVal==VARIANT_TRUE; }
static bool dialogRole(const VARIANT& v) {
  return v.vt==VT_BSTR && v.bstrVal && (!_wcsicmp(v.bstrVal,L"dialog") || !_wcsicmp(v.bstrVal,L"alertdialog"));
}
static bool allowedCandidate(bool owned,bool document,bool dialog,bool context,int candidates) {
  return owned && !document && dialog && context && candidates==1;
}
static bool credentialText(const std::wstring& input) {
  std::wstring text=input;std::transform(text.begin(),text.end(),text.begin(),towlower);
  for(auto word:{L"credential",L"identity",L"bluetooth",L"phone",L"qr code",L"another device",L"wallet"})
    if(text.find(word)!=std::wstring::npos)return true;
  return false;
}
struct Counters {int windows=0,buttons=0,visible=0,documents=0,dialogs=0,contexts=0,unsupported=0;};
class Observer {
 public:
  ComPtr<IUIAutomation> uia;ComPtr<IUIAutomationTreeWalker> walker;DWORD pid;Counters counts;
  explicit Observer(DWORD p):pid(p) {
    check(CoCreateInstance(CLSID_CUIAutomation8,nullptr,CLSCTX_INPROC_SERVER,IID_PPV_ARGS(&uia)));
    check(uia->get_ControlViewWalker(&walker));
  }
  int integer(IUIAutomationElement* e,PROPERTYID id) {
    Value value;check(e->GetCurrentPropertyValueEx(id,TRUE,&value.v));
    if(value.v.vt!=VT_I4)throw std::runtime_error("Unexpected native property type");return value.v.lVal;
  }
  bool boolean(IUIAutomationElement* e,PROPERTYID id) {
    Value value;check(e->GetCurrentPropertyValueEx(id,TRUE,&value.v));
    if(value.v.vt!=VT_BOOL)throw std::runtime_error("Unexpected native property type");return value.v.boolVal==VARIANT_TRUE;
  }
  std::wstring text(IUIAutomationElement* e,PROPERTYID id) {
    Value value;check(e->GetCurrentPropertyValueEx(id,TRUE,&value.v));
    if(value.v.vt!=VT_BSTR)throw std::runtime_error("Unexpected native property type");return value.v.bstrVal?value.v.bstrVal:L"";
  }
  bool same(IUIAutomationElement* a,IUIAutomationElement* b){BOOL yes=FALSE;check(uia->CompareElements(a,b,&yes));return yes;}
  bool owned(IUIAutomationElement* e){return integer(e,UIA_ProcessIdPropertyId)==static_cast<int>(pid);}
  bool isDialog(IUIAutomationElement* e) {
    Value is,role;check(e->GetCurrentPropertyValueEx(UIA_IsDialogPropertyId,TRUE,&is.v));
    check(e->GetCurrentPropertyValueEx(UIA_AriaRolePropertyId,TRUE,&role.v));
    if(is.v.vt!=VT_BOOL && is.v.vt!=VT_UNKNOWN && is.v.vt!=VT_EMPTY)return false;
    if(role.v.vt!=VT_BSTR && role.v.vt!=VT_UNKNOWN && role.v.vt!=VT_EMPTY)return false;
    if(is.v.vt!=VT_BOOL && role.v.vt!=VT_BSTR)counts.unsupported++;
    return dialogBoolean(is.v)||dialogRole(role.v);
  }
  bool hasContext(IUIAutomationElement* dialog) {
    std::vector<ComPtr<IUIAutomationElement>> queue;ComPtr<IUIAutomationElement> root=dialog;queue.push_back(root);
    bool found=false;
    for(size_t index=0;index<queue.size();index++) {
      if(queue.size()>512)throw std::runtime_error("Native subtree bound exceeded");
      auto current=queue[index];if(!owned(current.Get()))return false;
      if(integer(current.Get(),UIA_ControlTypePropertyId)==UIA_DocumentControlTypeId)continue;
      found=found||credentialText(text(current.Get(),UIA_NamePropertyId));
      ComPtr<IUIAutomationElement> child;check(walker->GetFirstChildElement(current.Get(),&child));
      while(child){if(queue.size()>=512)throw std::runtime_error("Native subtree bound exceeded");queue.push_back(child);ComPtr<IUIAutomationElement> next;check(walker->GetNextSiblingElement(child.Get(),&next));child=next;}
    }return found;
  }
  bool eligible(IUIAutomationElement* button,IUIAutomationElement* window) {
    if(!owned(button)||integer(button,UIA_ControlTypePropertyId)!=UIA_ButtonControlTypeId||text(button,UIA_NamePropertyId)!=L"Cancel")return false;
    if(boolean(button,UIA_IsOffscreenPropertyId)||!boolean(button,UIA_IsEnabledPropertyId))return false;
    counts.visible++;ComPtr<IUIAutomationElement> current,dialog;check(walker->GetParentElement(button,&current));bool reached=false;
    for(int depth=0;current&&depth<30;depth++) {
      if(!owned(current.Get()))return false;
      if(integer(current.Get(),UIA_ControlTypePropertyId)==UIA_DocumentControlTypeId){counts.documents++;return false;}
      if(!dialog&&isDialog(current.Get())){dialog=current;counts.dialogs++;}
      if(same(current.Get(),window)){reached=true;break;}
      ComPtr<IUIAutomationElement> parent;check(walker->GetParentElement(current.Get(),&parent));current=parent;
    }
    if(!reached||!dialog)return false;
    if(!hasContext(dialog.Get()))return false;counts.contexts++;return allowedCandidate(true,false,true,true,1);
  }
};
static bool selfTest() {
  Value value;value.v.vt=VT_BOOL;value.v.boolVal=VARIANT_TRUE;if(!dialogBoolean(value.v))return false;
  value.v.boolVal=VARIANT_FALSE;if(dialogBoolean(value.v))return false;
  value.v.vt=VT_I4;value.v.lVal=-1;if(dialogBoolean(value.v)||dialogRole(value.v))return false;
  value.v.vt=VT_EMPTY;if(dialogBoolean(value.v)||dialogRole(value.v))return false;
  value.v.vt=VT_UNKNOWN;value.v.punkVal=nullptr;if(dialogBoolean(value.v)||dialogRole(value.v))return false;
  value.v.vt=VT_BSTR;value.v.bstrVal=SysAllocString(L"alertdialog");if(!dialogRole(value.v))return false;
  VariantClear(&value.v);value.v.vt=VT_BSTR;value.v.bstrVal=SysAllocString(L"pane");if(dialogRole(value.v))return false;
  if(!allowedCandidate(true,false,true,true,1))return false;
  if(allowedCandidate(false,false,true,true,1)||allowedCandidate(true,true,true,true,1)||allowedCandidate(true,false,false,true,1)||allowedCandidate(true,false,true,false,1)||allowedCandidate(true,false,true,true,2))return false;
  ComPtr<IUIAutomation> native;check(CoCreateInstance(CLSID_CUIAutomation8,nullptr,CLSCTX_INPROC_SERVER,IID_PPV_ARGS(&native)));
  return true; // COM creation/QI only; no root element or application enumeration.
}
int wmain(int argc,wchar_t** argv) {
  HRESULT initialized=CoInitializeEx(nullptr,COINIT_MULTITHREADED);
  if(FAILED(initialized))return 3;
  struct ComLifetime {~ComLifetime(){CoUninitialize();}} comLifetime;
  try {
    if(argc==2&&std::wstring(argv[1])==L"--self-test") {
      if(!selfTest())throw std::runtime_error("Compatibility self-test failed");
      std::cout<<"{\"state\":\"NATIVE_ABI_SELF_TEST_PASS\",\"windows_enumerated\":false,\"controls_invoked\":false}";return 0;
    }
    if(argc!=4)throw std::runtime_error("Owned process identity arguments required");
    if(_wcsicmp(argv[2],L"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"))throw std::runtime_error("Unexpected browser executable");
    DWORD pid=std::stoul(argv[1]);ULONGLONG notBefore=std::stoull(argv[3]);
    HANDLE process=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE,FALSE,pid);
    if(!process)throw std::runtime_error("Owned process unavailable");
    struct Close {HANDLE h;~Close(){CloseHandle(h);}} close{process};
    wchar_t exe[32768];DWORD length=32768;FILETIME created,exited,kernel,user;
    if(!QueryFullProcessImageNameW(process,0,exe,&length)||_wcsicmp(exe,argv[2])||!GetProcessTimes(process,&created,&exited,&kernel,&user))throw std::runtime_error("Owned process identity mismatch");
    ULARGE_INTEGER creation;creation.LowPart=created.dwLowDateTime;creation.HighPart=created.dwHighDateTime;
    auto milliseconds=creation.QuadPart/10000-11644473600000ULL;
    if(milliseconds+2000<notBefore||milliseconds>notBefore+10000||WaitForSingleObject(process,0)!=WAIT_TIMEOUT)throw std::runtime_error("Owned process generation mismatch");
    Observer observer(pid);ComPtr<IUIAutomationElement> root;check(observer.uia->GetRootElement(&root));
    Value pidValue;pidValue.v.vt=VT_I4;pidValue.v.lVal=pid;ComPtr<IUIAutomationCondition> condition;
    check(observer.uia->CreatePropertyCondition(UIA_ProcessIdPropertyId,pidValue.v,&condition));
    ComPtr<IUIAutomationElementArray> windows;check(root->FindAll(TreeScope_Children,condition.Get(),&windows));int size=0;check(windows->get_Length(&size));if(size>16)throw std::runtime_error("Owned window bound exceeded");
    struct Candidate{ComPtr<IUIAutomationElement> button,window;};std::vector<Candidate> candidates;
    for(int i=0;i<size;i++) {
      ComPtr<IUIAutomationElement> window;check(windows->GetElement(i,&window));
      if(observer.text(window.Get(),UIA_ClassNamePropertyId)!=L"Chrome_WidgetWin_1")continue;observer.counts.windows++;
      Value buttonValue;buttonValue.v.vt=VT_I4;buttonValue.v.lVal=UIA_ButtonControlTypeId;ComPtr<IUIAutomationCondition> buttonsCondition;
      check(observer.uia->CreatePropertyCondition(UIA_ControlTypePropertyId,buttonValue.v,&buttonsCondition));
      ComPtr<IUIAutomationElementArray> buttons;check(window->FindAll(TreeScope_Descendants,buttonsCondition.Get(),&buttons));int count=0;check(buttons->get_Length(&count));if(count>512)throw std::runtime_error("Owned button bound exceeded");
      for(int j=0;j<count;j++){ComPtr<IUIAutomationElement> button;check(buttons->GetElement(j,&button));if(observer.text(button.Get(),UIA_NamePropertyId)!=L"Cancel")continue;observer.counts.buttons++;if(observer.eligible(button.Get(),window.Get()))candidates.push_back({button,window});}
    }
    if(candidates.size()!=1){auto c=observer.counts;std::cout<<"{\"state\":\"NO_UNAMBIGUOUS_NATIVE_CHOOSER\",\"native_cancel_candidates\":"<<candidates.size()<<",\"owned_class_windows\":"<<c.windows<<",\"cancel_buttons\":"<<c.buttons<<",\"enabled_onscreen\":"<<c.visible<<",\"document_rejections\":"<<c.documents<<",\"native_dialog_matches\":"<<c.dialogs<<",\"credential_context_matches\":"<<c.contexts<<",\"unsupported_dialog_properties\":"<<c.unsupported<<"}";return 2;}
    if(WaitForSingleObject(process,0)!=WAIT_TIMEOUT||!observer.eligible(candidates[0].button.Get(),candidates[0].window.Get()))throw std::runtime_error("Native chooser changed before invocation");
    ComPtr<IUIAutomationInvokePattern> invoke;check(candidates[0].button->GetCurrentPatternAs(UIA_InvokePatternId,IID_PPV_ARGS(&invoke)));check(invoke->Invoke());
    std::cout<<"{\"state\":\"NATIVE_CANCEL_INVOKED\",\"mechanism\":\"Native UIA InvokePattern with proven dialog ancestry\"}";
    return 0;
  }catch(...){std::cerr<<"Native chooser guard failed";return 3;}
}
