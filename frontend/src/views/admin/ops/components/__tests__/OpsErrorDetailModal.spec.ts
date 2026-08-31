import { flushPromises, shallowMount } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import OpsErrorDetailModal from '../OpsErrorDetailModal.vue'

const mocks = vi.hoisted(() => ({
  getRequestErrorDetail: vi.fn(),
  listRequestErrorUpstreamErrors: vi.fn(),
  downloadErrorPayload: vi.fn()
}))

vi.mock('@/api/admin/ops', () => ({
  opsAPI: {
    getRequestErrorDetail: mocks.getRequestErrorDetail,
    getUpstreamErrorDetail: vi.fn(),
    listRequestErrorUpstreamErrors: mocks.listRequestErrorUpstreamErrors,
    downloadErrorPayload: mocks.downloadErrorPayload
  }
}))

vi.mock('@/stores', () => ({
  useAppStore: () => ({ showError: vi.fn() })
}))

vi.mock('vue-i18n', async (importOriginal) => {
  const actual = await importOriginal<typeof import('vue-i18n')>()
  return {
    ...actual,
    useI18n: () => ({ t: (key: string) => key })
  }
})

describe('OpsErrorDetailModal', () => {
  beforeEach(() => {
    mocks.getRequestErrorDetail.mockReset()
    mocks.listRequestErrorUpstreamErrors.mockReset()
    mocks.downloadErrorPayload.mockReset()
    mocks.listRequestErrorUpstreamErrors.mockResolvedValue({ items: [] })
  })

  it('prioritizes upstream root cause and deduplicates diagnostic payloads', async () => {
    mocks.getRequestErrorDetail.mockResolvedValue({
      id: 1,
      created_at: '2026-08-19T00:00:00Z',
      phase: 'request',
      type: 'upstream_error',
      error_owner: 'provider',
      error_source: 'gateway',
      severity: 'P1',
      status_code: 502,
      upstream_status_code: 429,
      platform: 'openai',
      model: 'gpt-5.6',
      resolved: false,
      request_id: 'rid-1',
      message: 'All available accounts exhausted',
      error_body: '{"error":"same"}',
      upstream_error_message: 'provider rate limit exhausted',
      upstream_error_detail: '{"error":"same"}',
      upstream_errors: '[]',
      account_name: 'account',
      group_name: 'group',
      is_business_limited: false
    })

    const wrapper = shallowMount(OpsErrorDetailModal, {
      props: { show: true, errorId: 1, errorType: 'request' },
      global: {
        stubs: {
          BaseDialog: { template: '<div><slot /></div>' },
          Icon: true
        }
      }
    })
    await flushPromises()

    expect(wrapper.text()).toContain('provider rate limit exhausted')
    expect(wrapper.text()).toContain('admin.ops.errorDetail.upstreamStatus')
    expect(wrapper.text()).toContain('429')
    expect(wrapper.findAll('pre')).toHaveLength(2)
    expect(wrapper.text()).not.toContain('admin.ops.errorDetail.payloads.upstream_detail')
  })

  it('shows complete HTTP2WS payload metadata and downloads through the admin endpoint', async () => {
    mocks.getRequestErrorDetail.mockResolvedValue({
      id: 9,
      created_at: '2026-08-30T08:00:00Z',
      phase: 'upstream',
      type: 'upstream_error',
      error_owner: 'provider',
      error_source: 'upstream_http',
      severity: 'P1',
      status_code: 502,
      platform: 'openai',
      model: 'gpt-5.6-sol',
      resolved: false,
      request_id: 'rid-full',
      message: 'Invalid request',
      error_body: '{}',
      is_business_limited: false,
      request_payloads: [{
        id: 12,
        kind: 'ws',
        sha256: 'a'.repeat(64),
        payload_bytes: 2 * 1024 * 1024,
        created_at: '2026-08-30T08:00:00Z',
        attempts: [{
          sequence_no: 1,
          attempt_no: 1,
          account_id: 23,
          conn_id: 'oa_ws_1',
          connection_reused: true,
          write_succeeded: true,
          created_at: '2026-08-30T08:00:00Z'
        }]
      }]
    })
    mocks.downloadErrorPayload.mockResolvedValue(new Blob(['exact']))
    const createObjectURL = vi.fn(() => 'blob:test')
    const revokeObjectURL = vi.fn()
    Object.defineProperty(URL, 'createObjectURL', { configurable: true, value: createObjectURL })
    Object.defineProperty(URL, 'revokeObjectURL', { configurable: true, value: revokeObjectURL })
    const anchorClick = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})

    const wrapper = shallowMount(OpsErrorDetailModal, {
      props: { show: true, errorId: 9, errorType: 'request' },
      global: {
        stubs: {
          BaseDialog: { template: '<div><slot /></div>' },
          Icon: true
        }
      }
    })
    await flushPromises()

    expect(wrapper.text()).toContain('admin.ops.errorDetail.requestPayloads')
    expect(wrapper.text()).toContain('2.00 MiB')
    expect(wrapper.text()).toContain('oa_ws_1')
    const downloadButton = wrapper.findAll('button').find(button => button.text().includes('admin.ops.errorDetail.downloadRequestPayload'))
    expect(downloadButton).toBeTruthy()
    await downloadButton!.trigger('click')
    await flushPromises()
    expect(mocks.downloadErrorPayload).toHaveBeenCalledWith(9, 12)
    expect(createObjectURL).toHaveBeenCalled()
    expect(revokeObjectURL).toHaveBeenCalledWith('blob:test')
    expect(anchorClick).toHaveBeenCalled()
  })
})
