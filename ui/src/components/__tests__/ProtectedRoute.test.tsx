/**
 * Unit Tests for ProtectedRoute and Route Guards
 * 
 * Tests authentication-based routing, role-based access control,
 * and redirects for different user types.
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
        checkingOnboarding: false,
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

    it('should show loading spinner when checking onboarding', () => {
      mockUseAuth.mockReturnValue({
        isLoading: false,
        isAuthenticated: true,
        user: { id: 1 },
        checkingOnboarding: true,
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
    })
  })

  describe('authentication', () => {
    it('should redirect to login when not authenticated', () => {
      mockUseAuth.mockReturnValue({
        isLoading: false,
        isAuthenticated: false,
        user: null,
        checkingOnboarding: false,
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
        user: { id: 1, user_type: 'administrator' },
        checkingOnboarding: false,
        isAdministrator: true,
        isVendor: false,
        isApplicant: false,
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
        checkingOnboarding: false,
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

  describe('role-based access', () => {
    it('should allow access when user type matches allowedTypes', () => {
      mockUseAuth.mockReturnValue({
        isLoading: false,
        isAuthenticated: true,
        user: { id: 1, user_type: 'administrator' },
        checkingOnboarding: false,
        isAdministrator: true,
        isVendor: false,
        isApplicant: false,
      })

      renderWithoutRouter(
        <MemoryRouter initialEntries={['/admin']}>
          <Routes>
            <Route
              path="/admin"
              element={
                <ProtectedRoute allowedTypes={['administrator']}>
                  <TestComponent />
                </ProtectedRoute>
              }
            />
          </Routes>
        </MemoryRouter>
      )

      expect(screen.getByText('Protected Content')).toBeInTheDocument()
    })

    it('should redirect when user type does not match allowedTypes', () => {
      mockUseAuth.mockReturnValue({
        isLoading: false,
        isAuthenticated: true,
        user: { id: 1, user_type: 'applicant' },
        checkingOnboarding: false,
        isAdministrator: false,
        isVendor: false,
        isApplicant: true,
      })

      renderWithoutRouter(
        <MemoryRouter initialEntries={['/admin']}>
          <Routes>
            <Route path="/" element={<HomeComponent />} />
            <Route
              path="/admin"
              element={
                <ProtectedRoute allowedTypes={['administrator']}>
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

    it('should allow access when user matches any of multiple allowedTypes', () => {
      mockUseAuth.mockReturnValue({
        isLoading: false,
        isAuthenticated: true,
        user: { id: 1, user_type: 'vendor' },
        checkingOnboarding: false,
        isAdministrator: false,
        isVendor: true,
        isApplicant: false,
      })

      renderWithoutRouter(
        <MemoryRouter initialEntries={['/dashboard']}>
          <Routes>
            <Route
              path="/dashboard"
              element={
                <ProtectedRoute allowedTypes={['administrator', 'vendor']}>
                  <TestComponent />
                </ProtectedRoute>
              }
            />
          </Routes>
        </MemoryRouter>
      )

      expect(screen.getByText('Protected Content')).toBeInTheDocument()
    })

    it('should use custom unauthorizedRedirect', () => {
      mockUseAuth.mockReturnValue({
        isLoading: false,
        isAuthenticated: true,
        user: { id: 1, user_type: 'applicant' },
        checkingOnboarding: false,
        isAdministrator: false,
        isVendor: false,
        isApplicant: true,
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
                  allowedTypes={['administrator']}
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
        user: { id: 1, user_type: 'administrator' },
        checkingOnboarding: false,
        isAdministrator: true,
        isVendor: false,
        isApplicant: false,
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
        user: { id: 1, user_type: 'vendor' },
        checkingOnboarding: false,
        isAdministrator: false,
        isVendor: true,
        isApplicant: false,
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
        user: { id: 1, user_type: 'vendor', needsOnboarding: false },
        checkingOnboarding: false,
        isAdministrator: false,
        isVendor: true,
        isApplicant: false,
      })

      renderWithoutRouter(
        <MemoryRouter initialEntries={['/vendor']}>
          <Routes>
            <Route
              path="/vendor"
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

    it('should redirect to onboarding if vendor needs onboarding', () => {
      mockUseAuth.mockReturnValue({
        isLoading: false,
        isAuthenticated: true,
        user: { id: 1, user_type: 'vendor', needsOnboarding: true },
        checkingOnboarding: false,
        isAdministrator: false,
        isVendor: true,
        isApplicant: false,
      })

      const OnboardingPage = () => <div>Onboarding Page</div>

      renderWithoutRouter(
        <MemoryRouter initialEntries={['/vendor']}>
          <Routes>
            <Route path="/onboarding" element={<OnboardingPage />} />
            <Route
              path="/vendor"
              element={
                <VendorRoute>
                  <TestComponent />
                </VendorRoute>
              }
            />
          </Routes>
        </MemoryRouter>
      )

      expect(screen.getByText('Onboarding Page')).toBeInTheDocument()
      expect(screen.queryByText('Protected Content')).not.toBeInTheDocument()
    })

    it('should deny non-vendors', () => {
      mockUseAuth.mockReturnValue({
        isLoading: false,
        isAuthenticated: true,
        user: { id: 1, user_type: 'applicant' },
        checkingOnboarding: false,
        isAdministrator: false,
        isVendor: false,
        isApplicant: true,
      })

      renderWithoutRouter(
        <MemoryRouter initialEntries={['/vendor']}>
          <Routes>
            <Route path="/" element={<HomeComponent />} />
            <Route
              path="/vendor"
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
    })
  })

  describe('ApplicantRoute', () => {
    it('should allow applicants', () => {
      mockUseAuth.mockReturnValue({
        isLoading: false,
        isAuthenticated: true,
        user: { id: 1, user_type: 'applicant', needsOnboarding: false },
        checkingOnboarding: false,
        isAdministrator: false,
        isVendor: false,
        isApplicant: true,
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

    it('should redirect to onboarding if applicant needs onboarding', () => {
      mockUseAuth.mockReturnValue({
        isLoading: false,
        isAuthenticated: true,
        user: { id: 1, user_type: 'applicant', needsOnboarding: true },
        checkingOnboarding: false,
        isAdministrator: false,
        isVendor: false,
        isApplicant: true,
      })

      const OnboardingPage = () => <div>Onboarding Page</div>

      renderWithoutRouter(
        <MemoryRouter initialEntries={['/applicant']}>
          <Routes>
            <Route path="/onboarding" element={<OnboardingPage />} />
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

      expect(screen.getByText('Onboarding Page')).toBeInTheDocument()
    })

    it('should deny non-applicants', () => {
      mockUseAuth.mockReturnValue({
        isLoading: false,
        isAuthenticated: true,
        user: { id: 1, user_type: 'administrator' },
        checkingOnboarding: false,
        isAdministrator: true,
        isVendor: false,
        isApplicant: false,
      })

      renderWithoutRouter(
        <MemoryRouter initialEntries={['/applicant']}>
          <Routes>
            <Route path="/" element={<HomeComponent />} />
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

      expect(screen.getByText('Home Page')).toBeInTheDocument()
    })
  })
})
