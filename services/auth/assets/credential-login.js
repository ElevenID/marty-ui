(function () {
    var body = document.body;
    var nonce = body ? body.getAttribute('data-nonce') : '';
    var dcApiRequestUrl = body ? body.getAttribute('data-dc-api-request-url') : '';
    var dcApiSubmitUrl = body ? body.getAttribute('data-dc-api-submit-url') : '';
    var dcApiProtocol = body ? body.getAttribute('data-dc-api-protocol') : 'openid4vp-v1-signed';
  var qrSection = document.getElementById('qr-section');
  var mobileSection = document.getElementById('mobile-section');
  var qrFallback = document.getElementById('qr-fallback');
  var status = document.getElementById('status');
    var walletSelect = document.getElementById('wallet-select');
    var platformSelect = document.getElementById('platform-select');
    var walletLink = document.getElementById('wallet-link');
    var walletHelp = document.getElementById('wallet-help');
    var userAgent = navigator.userAgent || '';
    var dcApiRequestJwt = '';
    var dcApiPrefetch = null;

    function supportsDigitalCredentials() {
        if (!window.isSecureContext || !dcApiRequestUrl || !dcApiSubmitUrl) {
            return false;
        }
        if (typeof DigitalCredential === 'undefined') {
            return false;
        }
        if (!navigator.credentials || typeof navigator.credentials.get !== 'function') {
            return false;
        }
        try {
            return !!DigitalCredential.userAgentAllowsProtocol(dcApiProtocol);
        } catch (error) {
            return false;
        }
    }

    var dcApiSupported = supportsDigitalCredentials();

  function setStatus(html) {
    if (status) {
      status.innerHTML = html;
    }
  }

    function escapeHtml(value) {
        return String(value == null ? '' : value)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    function renderVerificationFailure(data) {
        var message = data && data.message ? data.message : 'Verification failed.';
        var detail = data && data.detail ? data.detail : '';
        var html = '<span class="err">' + escapeHtml(message) + '</span>';
        if (detail) {
            html += '<div class="status-detail">' + escapeHtml(detail) + '</div>';
        }
        html += '<div class="status-detail"><a href="/v1/auth/credential-login">Try again</a></div>';
        return html;
    }

  function showMobile() {
    if (qrSection) {
      qrSection.style.display = 'none';
    }
    if (mobileSection) {
      mobileSection.style.display = 'block';
    }
  }

  function showQr() {
    if (qrFallback) {
      qrFallback.style.display = 'block';
    }
  }

    function formatDcApiError(error) {
        if (!error) {
            return 'Wallet request failed.';
        }
        if (typeof error === 'string') {
            return error;
        }
        if (error.error_description) {
            return error.error_description;
        }
        if (error.detail) {
            if (typeof error.detail === 'string') {
                return error.detail;
            }
            if (error.detail.error_description) {
                return error.detail.error_description;
            }
            if (error.detail.error) {
                return error.detail.error;
            }
        }
        if (error.name === 'NotAllowedError') {
            return 'Wallet request was canceled.';
        }
        if (error.message) {
            return error.message;
        }
        return 'Wallet request failed.';
    }

    function prefetchDigitalCredentialRequest() {
        if (!dcApiSupported || !dcApiRequestUrl || dcApiRequestJwt || dcApiPrefetch) {
            return;
        }

        dcApiPrefetch = fetch(dcApiRequestUrl, {
            credentials: 'same-origin',
            headers: { Accept: 'application/oauth-authz-req+jwt' }
        })
            .then(function (response) {
                if (!response.ok) {
                    throw new Error('Failed to prepare wallet request.');
                }
                return response.text();
            })
            .then(function (requestJwt) {
                dcApiRequestJwt = requestJwt;
                return requestJwt;
            })
            .catch(function (error) {
                console.warn('Digital Credentials request prefetch failed', error);
            })
            .finally(function () {
                dcApiPrefetch = null;
            });
    }

    function setWalletBusy(isBusy) {
        if (!walletLink) {
            return;
        }
        if (isBusy) {
            walletLink.setAttribute('aria-disabled', 'true');
            walletLink.setAttribute('data-busy', 'true');
            walletLink.style.pointerEvents = 'none';
            walletLink.style.opacity = '0.75';
            return;
        }
        walletLink.removeAttribute('aria-disabled');
        walletLink.removeAttribute('data-busy');
        walletLink.style.pointerEvents = '';
        walletLink.style.opacity = '';
    }

    function submitDigitalCredential(credential) {
        return fetch(dcApiSubmitUrl, {
            method: 'POST',
            credentials: 'same-origin',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                protocol: credential && credential.protocol ? credential.protocol : dcApiProtocol,
                origin: window.location.origin,
                data: credential && credential.data ? credential.data : {}
            })
        }).then(function (response) {
            if (response.ok) {
                return response.json().catch(function () { return {}; });
            }
            return response.json()
                .catch(function () { return {}; })
                .then(function (payload) {
                    throw payload;
                });
        });
    }

    function launchDigitalCredentials() {
        if (!dcApiRequestJwt) {
            prefetchDigitalCredentialRequest();
            setStatus('<span class="err">Preparing the wallet chooser. Tap Open wallet again in a moment.</span>');
            setWalletBusy(false);
            return Promise.resolve();
        }

        return navigator.credentials.get({
            mediation: 'required',
            digital: {
                requests: [{
                    protocol: dcApiProtocol,
                    data: {
                        request: dcApiRequestJwt
                    }
                }]
            }
        })
            .then(function (credential) {
                if (!credential || !credential.data) {
                    throw new Error('Wallet returned an empty credential response.');
                }
                if (credential.data.error) {
                    throw credential.data;
                }
                setStatus('<span class="spinner"></span> Wallet response received. Finalizing sign-in&hellip;');
                return submitDigitalCredential(credential);
            })
            .catch(function (error) {
                setStatus('<span class="err">' + formatDcApiError(error) + '</span>');
            })
            .finally(function () {
                setWalletBusy(false);
            });
    }

    function detectPlatform() {
        if (/Android/i.test(userAgent)) {
            return 'android';
    }
        if (/iPhone|iPad|iPod/i.test(userAgent)) {
            return 'ios';
        }
        return 'generic';
    }

    function selectedPlatform() {
        var platform = platformSelect ? platformSelect.value : 'auto';
        return platform === 'auto' ? detectPlatform() : platform;
    }

    function syncWalletLaunch() {
        if (!walletSelect) {
            return;
        }

        var selectedOption = walletSelect.options[walletSelect.selectedIndex];
        if (!selectedOption) {
            return;
        }

        try {
            window.localStorage.setItem('marty.credential_login.wallet', walletSelect.value || '');
        } catch (storageError) {
            // Private mode or quota errors are non-fatal.
        }

        var href = selectedOption.getAttribute('data-link') || '';
        var platform = selectedPlatform();
        var label = selectedOption.textContent || 'selected wallet';
        var description = selectedOption.getAttribute('data-description') || 'Select your wallet, then tap Open wallet.';

        if (platform === 'android') {
            href = selectedOption.getAttribute('data-android-link') || href;
        } else if (platform === 'ios') {
            href = selectedOption.getAttribute('data-ios-link') || href;
        }

        if (walletLink && href) {
            walletLink.setAttribute('href', href);
            walletLink.setAttribute('aria-label', 'Open wallet with ' + label);
        }

        if (walletHelp) {
            walletHelp.textContent = dcApiSupported
                ? 'Your browser will open the system wallet chooser on this device. Use the QR code if you prefer another device.'
                : description;
    }
    }

    function restoreWalletPreference() {
        if (!walletSelect) {
            return;
        }
        var storedWallet = '';
        var storedPlatform = '';
        try {
            storedWallet = window.localStorage.getItem('marty.credential_login.wallet') || '';
            storedPlatform = window.localStorage.getItem('marty.credential_login.platform') || '';
        } catch (storageError) {
            return;
        }
        if (storedWallet) {
            for (var i = 0; i < walletSelect.options.length; i += 1) {
                if (walletSelect.options[i].value === storedWallet) {
                    walletSelect.selectedIndex = i;
                    break;
                }
            }
        }
        if (storedPlatform && platformSelect) {
            for (var j = 0; j < platformSelect.options.length; j += 1) {
                if (platformSelect.options[j].value === storedPlatform) {
                    platformSelect.selectedIndex = j;
                    break;
                }
            }
        }
    }

    function persistPlatformPreference() {
        if (!platformSelect) {
            return;
        }
        try {
            window.localStorage.setItem('marty.credential_login.platform', platformSelect.value || '');
        } catch (storageError) {
            // Non-fatal.
        }
    }

  var showMobileButton = document.querySelector('[data-action="show-mobile"]');
  if (showMobileButton) {
    showMobileButton.addEventListener('click', showMobile);
  }

  var showQrButton = document.querySelector('[data-action="show-qr"]');
  if (showQrButton) {
    showQrButton.addEventListener('click', showQr);
  }

    if (walletSelect) {
        restoreWalletPreference();
        walletSelect.addEventListener('change', syncWalletLaunch);
        syncWalletLaunch();
    }

    if (platformSelect) {
        platformSelect.addEventListener('change', function () {
            persistPlatformPreference();
            syncWalletLaunch();
        });
        syncWalletLaunch();
    }

    if (walletLink) {
        walletLink.addEventListener('click', function (event) {
            if (!dcApiSupported) {
                return;
            }
            event.preventDefault();
            if (walletLink.getAttribute('data-busy') === 'true') {
                return;
            }
            setWalletBusy(true);
            setStatus('<span class="spinner"></span> Opening your wallet chooser&hellip;');
            launchDigitalCredentials();
        });
    }

    if (dcApiSupported) {
        prefetchDigitalCredentialRequest();
    }

    if (/Android|iPhone|iPad|iPod|Mobile/i.test(userAgent)) {
        showMobile();
    }

    if (!nonce) {
        setStatus('<span class="err">Login session missing. <a href="/v1/auth/credential-login">Try again</a></span>');
        return;
    }

    var attempts = 0;
    var maxAttempts = 180;
    var timer = setInterval(function () {
        attempts += 1;
        if (attempts > maxAttempts) {
            clearInterval(timer);
            setStatus('<span class="err">Timed out. <a href="/v1/auth/credential-login">Try again</a></span>');
            return;
    }

    fetch('/v1/auth/credential-login/status?nonce=' + encodeURIComponent(nonce), {
      credentials: 'same-origin'
    })
      .then(function (response) { return response.json(); })
      .then(function (data) {
        if (data.status === 'completed') {
          clearInterval(timer);
          setStatus('<span class="done">&#10003; Verified! Redirecting&hellip;</span>');
          window.location.href = data.redirect_to || '/';
        } else if (data.status === 'failed') {
          clearInterval(timer);
                    setStatus(renderVerificationFailure(data));
        } else if (data.status === 'expired') {
          clearInterval(timer);
          setStatus('<span class="err">Login session expired. <a href="/v1/auth/credential-login">Try again</a></span>');
        }
      })
      .catch(function () {
        // Keep polling through transient network hiccups.
      });
  }, 2500);
})();
