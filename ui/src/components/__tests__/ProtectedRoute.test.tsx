/**
 * Unit Tests for ProtectedRoute and Route Guards
 * 
 * Tests authentication-based routing and capability-based access control.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { renderWithoutRouter, screen } from '@test/utils'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import ProtectedRoute, { AdminRoute, VendorRoute, ApplicantRoute } from '../ProtectedRoute'
import * as useAuthModule from '@hooks/useAuth'

// Mock useAuth hook
const mockUseAuth = vi.fn()
vi.spyOn(useAuthModule, 'useAuth').mockImplementation(mockUseAuth)

describe('ProtectedRoute', () => {
  const TestComponent = () => <div>Protected Content</div>
  const LoginComponent = () => <div>Login Page</div>
  const HomeComponent = () => <div>Home Page</div>

  beforeEach(() => {
    vi.clearAllMocks()
  })

  describe('loading states', () => {
    it('should show loading spinner when auth is loading', () => {
      mockUseAuth.mockReturnValue({
        isLoading: true,
        isAuthenticated: false,
        user: null,
      })

      renderWithoutRouter(
        <MemoryRouter initialEntries={['/protected']}>
          <Routes>
            <Route
              path="/protected"
              element={
                <ProtectedRoute>
                  <TestComponent />
                </ProtectedRoute>
              }
            />
          </Routes>
        </MemoryRouter>
      )

      expect(screen.getByText('Checking authentication...')).toBeInTheDocument()
      expect(screen.queryByText('Protected Content')).not.toBeInTheDocument()
    })
  })

  describe('authentication', () => {
    it('should redirect to login when not authenticated', () => {
      mockUseAuth.mockReturnValue({
        isLoading: false,
        isAuthenticated: false,
        user: null,
      })

      renderWithoutRouter(
        <MemoryRouter initialEntries={['/protected']}>
          <Routes>
            <Route path="/login" element={<LoginComponent />} />
            <Route
              path="/protected"
              element={
                <ProtectedRoute>
                  <TestComponent />
                </ProtectedRoute>
              }
            />
          </Routes>
        </MemoryRouter>
      )

      expect(screen.getByText('Login Page')).toBeInTheDocument()
      expect(screen.queryByText('Protected Content')).not.toBeInTheDocument()
    })

    it('should render children when authenticated', () => {
      mockUseAuth.mockReturnValue({
        isLoading: false,
        isAuthenticated: true,
        user: { id: 1, capabilities: { 'admin:platform': true } },
        hasCapability: (capability: string) => capability === 'admin:platform',
      })

      renderWithoutRouter(
        <MemoryRouter initialEntries={['/protected']}>
          <Routes>
            <Route
              path="/protected"
              element={
                <ProtectedRoute>
                  <TestComponent />
                </ProtectedRoute>
              }
            />
          </Routes>
        </MemoryRouter>
      )

      expect(screen.getByText('Protected Content')).toBeInTheDocument()
    })

    it('should use custom redirectTo path', () => {
      mockUseAuth.mockReturnValue({
        isLoading: false,
        isAuthenticated: false,
        user: null,
      })

      const CustomLogin = () => <div>Custom Login</div>

      renderWithoutRouter(
        <MemoryRouter initialEntries={['/protected']}>
          <Routes>
            <Route path="/custom-login" element={<CustomLogin />} />
            <Route
              path="/protected"
              element={
                <ProtectedRoute redirectTo="/custom-login">
                  <TestComponent />
                </ProtectedRoute>
              }
            />
          </Routes>
        </MemoryRouter>
      )

      expect(screen.getByText('Custom Login')).toBeInTheDocument()
    })
  })

  describe('capability-based access', () => {
    it('should allow access when user has required capability', () => {
      mockUseAuth.mockReturnValue({
        isLoading: false,
        isAuthenticated: true,
        user: { id: 1, capabilities: { 'admin:platform': true } },
        hasCapability: (capability: string) => capability === 'admin:platform',
      })

      renderWithoutRouter(
        <MemoryRouter initialEntries={['/admin']}>
          <Routes>
            <Route
              path="/admin"
              element={
                <ProtectedRoute requiredCapabilities={['admin:platform']}>
                  <TestComponent />
                </ProtectedRoute>
              }
            />
          </Routes>
        </MemoryRouter>
      )

      expect(screen.getByText('Protected Content')).toBeInTheDocument()
    })

    it('should redirect when user lacks required capability', () => {
      mockUseAuth.mockReturnValue({
        isLoading: false,
        isAuthenticated: true,
        user: { id: 1, capabilities: {} },
        hasCapability: () => false,
      })

      renderWithoutRouter(
        <MemoryRouter initialEntries={['/admin']}>
          <Routes>
            <Route path="/" element={<HomeComponent />} />
            <Route
              path="/admin"
              element={
                <ProtectedRoute requiredCapabilities={['admin:platform']}>
                  <TestComponent />
                </ProtectedRoute>
              }
            />
          </Routes>
        </MemoryRouter>
      )

      expect(screen.getByText('Home Page')).toBeInTheDocument()
      expect(screen.queryByText('Protected Content')).not.toBeInTheDocument()
    })

    it('should allow access when user matches any required capability', () => {
      mockUseAuth.mockReturnValue({
        isLoading: false,
        isAuthenticated: true,
        user: { id: 1, capabilities: { 'org:view': true } },
        hasCapability: (capability: string) => capability === 'org:view',
      })

      renderWithoutRouter(
        <MemoryRouter initialEntries={['/dashboard']}>
          <Routes>
            <Route
              path="/dashboard"
              element={
                <ProtectedRoute requiredCapabilities={['admin:platform', 'org:view']}>
                  <TestComponent />
                </ProtectedRoute>
              }
            />
          </Routes>
        </MemoryRouter>
      )

      expect(screen.getByText('Protected Content')).toBeInTheDocument()
    })

    it('should require all capabilities when configured', () => {
      mockUseAuth.mockReturnValue({
        isLoading: false,
        isAuthenticated: true,
        user: { id: 1, capabilities: { 'org:view': true } },
        hasCapability: (capability: string) => capability === 'org:view',
      })

      renderWithoutRouter(
        <MemoryRouter initialEntries={['/dashboard']}>
          <Routes>
            <Route path="/" element={<HomeComponent />} />
            <Route
              path="/dashboard"
              element={
                <ProtectedRoute
                  requiredCapabilities={['admin:platform', 'org:view']}
                  requireAllCapabilities
                >
                  <TestComponent />
                </ProtectedRoute>
              }
            />
          </Routes>
        </MemoryRouter>
      )

      expect(screen.getByText('Home Page')).toBeInTheDocument()
      expect(screen.queryByText('Protected Content')).not.toBeInTheDocument()
    })

    it('should use custom unauthorizedRedirect', () => {
      mockUseAuth.mockReturnValue({
        isLoading: false,
        isAuthenticated: true,
        user: { id: 1, capabilities: {} },
        hasCapability: () => false,
      })

      const AccessDenied = () => <div>Access Denied</div>

      renderWithoutRouter(
        <MemoryRouter initialEntries={['/admin']}>
          <Routes>
            <Route path="/access-denied" element={<AccessDenied />} />
            <Route
              path="/admin"
              element={
                <ProtectedRoute
                  requiredCapabilities={['admin:platform']}
                  unauthorizedRedirect="/access-denied"
                >
                  <TestComponent />
                </ProtectedRoute>
              }
            />
          </Routes>
        </MemoryRouter>
      )

      expect(screen.getByText('Access Denied')).toBeInTheDocument()
    })
  })

  describe('AdminRoute', () => {
    it('should allow administrators', () => {
      mockUseAuth.mockReturnValue({
        isLoading: false,
        isAuthenticated: true,
        user: { id: 1, capabilities: { 'admin:platform': true } },
        hasCapability: (capability: string) => capability === 'admin:platform',
      })

      renderWithoutRouter(
        <MemoryRouter initialEntries={['/admin']}>
          <Routes>
            <Route
              path="/admin"
              element={
                <AdminRoute>
                  <TestComponent />
                </AdminRoute>
              }
            />
          </Routes>
        </MemoryRouter>
      )

      expect(screen.getByText('Protected Content')).toBeInTheDocument()
    })

    it('should deny non-administrators', () => {
      mockUseAuth.mockReturnValue({
        isLoading: false,
        isAuthenticated: true,
        user: { id: 1, capabilities: { 'org:view': true } },
        hasCapability: (capability: string) => capability === 'org:view',
      })

      renderWithoutRouter(
        <MemoryRouter initialEntries={['/admin']}>
          <Routes>
            <Route path="/" element={<HomeComponent />} />
            <Route
              path="/admin"
              element={
                <AdminRoute>
                  <TestComponent />
                </AdminRoute>
              }
            />
          </Routes>
        </MemoryRouter>
      )

      expect(screen.getByText('Home Page')).toBeInTheDocument()
    })
  })

  describe('VendorRoute', () => {
    it('should allow vendors', () => {
      mockUseAuth.mockReturnValue({
        isLoading: false,
        isAuthenticated: true,
        user: { id: 1, capabilities: { 'org:view': true } },
        hasCapability: (capability: string) => capability === 'org:view',
      })

      renderWithoutRouter(
        <MemoryRouter initialEntries={['/console']}>
          <Routes>
            <Route
              path="/console"
              element={
                <VendorRoute>
                  <TestComponent />
                </VendorRoute>
              }
            />
          </Routes>
        </MemoryRouter>
      )

      expect(screen.getByText('Protected Content')).toBeInTheDocument()
    })

    it('should deny users without org visibility capability', () => {
      mockUseAuth.mockReturnValue({
        isLoading: false,
        isAuthenticated: true,
        user: { id: 1, capabilities: {} },
        hasCapability: () => false,
      })

      renderWithoutRouter(
        <MemoryRouter initialEntries={['/console']}>
          <Routes>
            <Route path="/" element={<HomeComponent />} />
            <Route
              path="/console"
              element={
                <VendorRoute>
                  <TestComponent />
                </VendorRoute>
              }
            />
          </Routes>
        </MemoryRouter>
      )

      expect(screen.getByText('Home Page')).toBeInTheDocument()
      expect(screen.queryByText('Protected Content')).not.toBeInTheDocument()
    })
  })

  describe('ApplicantRoute', () => {
    it('should allow any authenticated user', () => {
      mockUseAuth.mockReturnValue({
        isLoading: false,
        isAuthenticated: true,
        user: { id: 1, capabilities: {} },
        hasCapability: () => false,
      })

      renderWithoutRouter(
        <MemoryRouter initialEntries={['/applicant']}>
          <Routes>
            <Route
              path="/applicant"
              element={
                <ApplicantRoute>
                  <TestComponent />
                </ApplicantRoute>
              }
            />
          </Routes>
        </MemoryRouter>
      )

      expect(screen.getByText('Protected Content')).toBeInTheDocument()
    })

    it('should redirect unauthenticated users to login', () => {
      mockUseAuth.mockReturnValue({
        isLoading: false,
        isAuthenticated: false,
        user: null,
        hasCapability: () => false,
      })

      renderWithoutRouter(
        <MemoryRouter initialEntries={['/applicant']}>
          <Routes>
            <Route path="/login" element={<LoginComponent />} />
            <Route
              path="/applicant"
              element={
                <ApplicantRoute>
                  <TestComponent />
                </ApplicantRoute>
              }
            />
          </Routes>
        </MemoryRouter>
      )

      expect(screen.getByText('Login Page')).toBeInTheDocument()
    })
  })
})
