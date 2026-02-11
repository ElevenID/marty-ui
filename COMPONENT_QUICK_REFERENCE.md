# Quick Reference: Using New marty-ui Components

This guide shows how to use the newly implemented foundation components and patterns in marty-ui.

## Loading States

### Replace CircularProgress with Skeletons

**Before:**
```jsx
if (loading) {
  return <CircularProgress />;
}
```

**After:**
```jsx
import { TableSkeleton } from '../components/common/skeletons';

if (loading) {
  return <TableSkeleton rows={5} columns={4} showActions={true} />;
}
```

**Available Skeletons:**
- `<TableSkeleton>` - For data tables
- `<CardSkeleton>` - For card grids  
- `<FormSkeleton>` - For forms
- `<PageSkeleton variant="list|detail|dashboard">` - For full pages

## Error Handling

### Use ErrorState Component

**Before:**
```jsx
if (error) {
  return <Alert severity="error">{error.message}</Alert>;
}
```

**After:**
```jsx
import ErrorState from '../components/common/ErrorState';

if (error) {
  return <ErrorState error={error} onRetry={loadData} variant="inline" />;
}
```

**Variants:**
- `full` - Full-page error (default)
- `inline` - Inline alert with expandable details
- `compact` - Compact alert for small sections

**Features:**
- Automatically parses structured API errors
- Shows user-friendly message + technical details
- Displays request ID and timestamp
- Copy details to clipboard
- Contact support integration
- Retry functionality

## Empty States

### Enhanced EmptyState with Prerequisites

**Before:**
```jsx
<EmptyState
  title="No templates yet"
  description="Create your first template."
  actionLabel="Create Template"
  actionPath="/console/templates/new"
/>
```

**After:**
```jsx
import EmptyState from '../components/common/EmptyState';

<EmptyState
  icon={TemplateIcon}
  title="No credential templates yet"
  description="Templates define the schema and format for credentials you issue."
  whyItMatters="Templates are required before you can issue credentials to users."
  prerequisites={[
    { label: 'Trust Profile', status: 'ready', path: '/console/trust/profiles' },
    { label: 'Signing Keys', status: 'blocked', path: '/console/deploy/signing-keys' },
  ]}
  actionLabel="Create Template"
  actionPath="/console/templates/new"
  docsUrl="https://docs.example.com/templates"
  exampleLabel="Load Example Template"
  onExampleClick={handleLoadExample}
/>
```

**Prerequisite Status:**
- `ready` - Green checkmark, ready to proceed
- `pending` - Yellow warning, needs attention
- `blocked` - Red error, must resolve first

**Effect:** If any prerequisite is `blocked` or `pending`, the action button is disabled.

## Permissions

### Check Permissions with usePermissions Hook

```jsx
import { usePermissions } from '../hooks/usePermissions';

function MyComponent() {
  const { can, canCreate, canEdit, canDelete } = usePermissions();
  
  return (
    <Box>
      {canCreate('template') && (
        <Button onClick={handleCreate}>Create Template</Button>
      )}
      
      {canDelete('template') && (
        <IconButton onClick={handleDelete}>
          <DeleteIcon />
        </IconButton>
      )}
    </Box>
  );
}
```

### Use Permission Components

#### PermissionGate - Conditional Rendering

```jsx
import { PermissionGate } from '../components/common/PermissionGate';

<PermissionGate resource="template" action="create">
  <Button onClick={handleCreate}>Create Template</Button>
</PermissionGate>
```

#### PermissionButton - Auto-Disabled with Tooltip

```jsx
import { PermissionButton } from '../components/common/PermissionGate';

<PermissionButton
  resource="template"
  action="delete"
  variant="contained"
  color="error"
  onClick={handleDelete}
>
  Delete Template
</PermissionButton>
```

**Result:** Button is automatically disabled if user lacks permission, with tooltip explaining why.

### Role-Based Permissions

**Roles:**
- `admin` - Full access to everything
- `dev` - Can create/edit resources, no team management
- `operator` - View-only, can manage flows and issuance

**Resources:**
- `trust`, `template`, `policy`, `deployment`, `flow`, `issuance`, `team`, `audit`, `org`, `signing-key`

**Actions:**
- `view`, `create`, `edit`, `delete`, `execute`

## API Services

### Use Unified API Pattern

**Before (old pattern):**
```javascript
import { apiClient } from './api';

export const getItems = async () => {
  const response = await apiClient.get('/v1/items');
  return response.data;
};
```

**After (new pattern):**
```javascript
import { get, post, patch, del } from './api';

export async function getItems() {
  return get('/v1/items');
}

export async function createItem(data) {
  return post('/v1/items', data);
}

export async function updateItem(id, data) {
  return patch(`/v1/items/${id}`, data);
}

export async function deleteItem(id) {
  return del(`/v1/items/${id}`);
}
```

**Benefits:**
- Automatic retry with exponential backoff (GET requests)
- Unified error response parsing
- Request ID tracking
- No need to access `.data` - returns data directly

### Handle API Errors

```jsx
const [loading, setLoading] = useState(true);
const [error, setError] = useState(null);

const loadData = async () => {
  setLoading(true);
  setError(null);
  try {
    const data = await myApi.getData();
    setMyData(data);
  } catch (err) {
    setError(err); // Structured error object
  } finally {
    setLoading(false);
  }
};

// In render:
if (loading) return <TableSkeleton />;
if (error) return <ErrorState error={error} onRetry={loadData} />;
```

## Page Structure

### Use ResourcePage Wrapper

```jsx
import ResourcePage from '../../common/ResourcePage';

const TABS = [
  { label: 'Overview', path: '/console/section/overview' },
  { label: 'Settings', path: '/console/section/settings' },
];

const BREADCRUMBS = [
  { label: 'Console', path: '/console' },
  { label: 'Section', path: '/console/section' },
];

export default function MyPage() {
  return (
    <ResourcePage
      title="My Resource"
      description="Manage your resources here"
      resourceName="Resources"
      buildPath="/console/section/new"
      tabs={TABS}
      breadcrumbs={BREADCRUMBS}
      icon={<MyIcon />}
    >
      {/* Page content */}
    </ResourcePage>
  );
}
```

## Form Wizards

### Use useWizard Hook

```jsx
import { useWizard } from '../hooks/useWizard';
import { useNavigate } from 'react-router-dom';

function MyWizard() {
  const navigate = useNavigate();
  
  const wizard = useWizard({
    steps: ['Basic Info', 'Configuration', 'Review'],
    initialData: { name: '', type: '' },
    validateStep: (stepIndex, data) => {
      if (stepIndex === 0) {
        return data.name && data.type;
      }
      return true;
    },
    onSubmit: async (data) => {
      await myApi.create(data);
    },
    onComplete: () => {
      navigate('/console/section');
    },
    onCancel: () => {
      navigate('/console/section');
    },
  });

  return (
    <Box>
      {/* Render step content based on wizard.activeStep */}
      {/* Use wizard.goNext(), wizard.goBack(), wizard.submit() */}
    </Box>
  );
}
```

## Notifications

### Show Toast Notifications

```jsx
import { useNotifications } from '../hooks/useNotifications';

function MyComponent() {
  const { showNotification } = useNotifications();
  
  const handleSave = async () => {
    try {
      await myApi.save(data);
      showNotification('Saved successfully', 'success');
    } catch (err) {
      showNotification('Failed to save', 'error');
    }
  };
}
```

**Severities:** `success`, `error`, `warning`, `info`

## Testing

### Test Component with Permissions

```javascript
import { render } from '@testing-library/react';
import { PermissionsProvider } from '../contexts/PermissionsContext';

test('shows create button for admin', () => {
  const { getByText } = render(
    <PermissionsProvider value={{ role: 'admin' }}>
      <MyComponent />
    </PermissionsProvider>
  );
  
  expect(getByText('Create')).toBeInTheDocument();
});
```

### Mock API Service

```javascript
import { vi } from 'vitest';
import * as myApi from '../services/myApi';

vi.mock('../services/myApi');

test('loads data on mount', async () => {
  myApi.getData.mockResolvedValue([{ id: 1, name: 'Test' }]);
  
  render(<MyComponent />);
  
  await waitFor(() => {
    expect(screen.getByText('Test')).toBeInTheDocument();
  });
});
```

## Common Patterns

### List Page Pattern

```jsx
import { useState, useEffect } from 'react';
import { TableSkeleton } from '../components/common/skeletons';
import ErrorState from '../components/common/ErrorState';
import EmptyState from '../components/common/EmptyState';
import ResourcePage from '../components/common/ResourcePage';

export default function ListPage() {
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    loadItems();
  }, []);

  const loadItems = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await myApi.listItems();
      setItems(Array.isArray(data) ? data : data.items || []);
    } catch (err) {
      setError(err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <ResourcePage
      title="My Items"
      description="Manage your items"
      buildPath="/console/items/new"
    >
      {loading && <TableSkeleton />}
      {error && <ErrorState error={error} onRetry={loadItems} />}
      {!loading && !error && items.length === 0 && (
        <EmptyState
          title="No items yet"
          description="Create your first item to get started."
          actionLabel="Create Item"
          actionPath="/console/items/new"
        />
      )}
      {!loading && !error && items.length > 0 && (
        <Table>{/* Render table */}</Table>
      )}
    </ResourcePage>
  );
}
```

---

## Migration Checklist

When updating an existing page to use new patterns:

- [ ] Replace `CircularProgress` with appropriate skeleton
- [ ] Replace `Alert` error messages with `<ErrorState>`
- [ ] Update empty states with `<EmptyState>` including prerequisites
- [ ] Add permission checks using `usePermissions()` or `<PermissionGate>`
- [ ] Update API service to use `get/post/patch/del` pattern
- [ ] Wrap page content in `<ResourcePage>` if it's a resource management page
- [ ] Add proper error handling with retry functionality
- [ ] Add loading skeletons that match final UI structure
- [ ] Test with all three user roles (admin/dev/operator)

---

**Questions?** Check the implementation in existing components:
- Signing Keys page: `ui/src/components/console/deploy/SigningKeysPage.jsx`
- Deployment Profiles: `ui/src/components/vendor/DeploymentProfileManager.jsx`
- Audit page: `ui/src/components/console/audit/AuditPage.jsx`
