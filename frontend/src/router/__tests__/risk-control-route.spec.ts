import { beforeEach, describe, expect, it, vi } from 'vitest'

const authStore = vi.hoisted(() => ({
  checkAuth: vi.fn(),
  isAuthenticated: true,
  isAdmin: true,
  isSimpleMode: false,
  hasPendingAuthSession: false,
}))

const appStore = vi.hoisted(() => ({
  siteName: 'Sub2API',
  backendModeEnabled: false,
  publicSettingsLoaded: false,
  cachedPublicSettings: null as null | Record<string, unknown>,
  fetchPublicSettings: vi.fn(async () => {
    appStore.cachedPublicSettings = {
      custom_menu_items: [],
      payment_enabled: false,
      risk_control_enabled: true,
    }
    appStore.publicSettingsLoaded = true
    return appStore.cachedPublicSettings
  }),
}))

vi.mock('@/stores/auth', () => ({
  useAuthStore: () => authStore,
}))

vi.mock('@/stores/app', () => ({
  useAppStore: () => appStore,
}))

vi.mock('@/stores/adminSettings', () => ({
  useAdminSettingsStore: () => ({
    customMenuItems: [],
  }),
}))

vi.mock('@/stores/adminCompliance', () => ({
  useAdminComplianceStore: () => ({
    initialized: true,
    fetchStatus: vi.fn(),
    requireAcknowledgement: vi.fn(),
  }),
}))

vi.mock('@/composables/useNavigationLoading', () => ({
  useNavigationLoadingState: () => ({
    startNavigation: vi.fn(),
    endNavigation: vi.fn(),
    isLoading: { value: false },
  }),
}))

vi.mock('@/composables/useRoutePrefetch', () => ({
  useRoutePrefetch: () => ({
    triggerPrefetch: vi.fn(),
    cancelPendingPrefetch: vi.fn(),
    resetPrefetchState: vi.fn(),
  }),
}))

vi.mock('@/api/setup', () => ({
  getSetupStatus: vi.fn().mockResolvedValue({ needs_setup: false }),
}))

describe('risk control route bootstrap', () => {
  beforeEach(() => {
    vi.resetModules()
    window.scrollTo = vi.fn()
    authStore.checkAuth.mockClear()
    authStore.isAuthenticated = true
    authStore.isAdmin = true
    authStore.isSimpleMode = false
    authStore.hasPendingAuthSession = false

    appStore.siteName = 'Sub2API'
    appStore.backendModeEnabled = false
    appStore.publicSettingsLoaded = false
    appStore.cachedPublicSettings = null
    appStore.fetchPublicSettings.mockClear()
    appStore.fetchPublicSettings.mockImplementation(async () => {
      appStore.cachedPublicSettings = {
        custom_menu_items: [],
        payment_enabled: false,
        risk_control_enabled: true,
      }
      appStore.publicSettingsLoaded = true
      return appStore.cachedPublicSettings
    })

    window.history.replaceState({}, '', '/')
  })

  it('loads public settings before enforcing the risk control feature flag on first navigation', async () => {
    const { default: router } = await import('@/router')

    await router.push('/admin/risk-control')

    expect(appStore.fetchPublicSettings).toHaveBeenCalledTimes(1)
    expect(router.currentRoute.value.fullPath).toBe('/admin/risk-control')
  })

  it('revalidates stale cached public settings before redirecting away from the risk control route', async () => {
    appStore.publicSettingsLoaded = true
    appStore.cachedPublicSettings = {
      custom_menu_items: [],
      payment_enabled: false,
      risk_control_enabled: false,
    }
    appStore.fetchPublicSettings.mockImplementation(async () => {
      appStore.cachedPublicSettings = {
        custom_menu_items: [],
        payment_enabled: false,
        risk_control_enabled: true,
      }
      appStore.publicSettingsLoaded = true
      return appStore.cachedPublicSettings
    })

    const { default: router } = await import('@/router')

    await router.push('/admin/risk-control')

    expect(appStore.fetchPublicSettings).toHaveBeenCalledTimes(1)
    expect(appStore.fetchPublicSettings).toHaveBeenCalledWith(true)
    expect(router.currentRoute.value.fullPath).toBe('/admin/risk-control')
  })
})
