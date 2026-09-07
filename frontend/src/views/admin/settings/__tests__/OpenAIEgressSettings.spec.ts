import { beforeEach, describe, expect, it, vi } from "vitest";
import { flushPromises, mount } from "@vue/test-utils";

import OpenAIEgressSettings from "../OpenAIEgressSettings.vue";

const { getSettings, updateSettings, testSettings, showSuccess } = vi.hoisted(() => ({
  getSettings: vi.fn(),
  updateSettings: vi.fn(),
  testSettings: vi.fn(),
  showSuccess: vi.fn(),
}));

vi.mock("@/api", () => ({
  adminAPI: {
    settings: {
      getOpenAIEgressSettings: getSettings,
      updateOpenAIEgressSettings: updateSettings,
      testOpenAIEgressSettings: testSettings,
    },
  },
}));

vi.mock("@/stores", () => ({
  useAppStore: () => ({ showSuccess }),
}));

vi.mock("vue-i18n", () => ({
  useI18n: () => ({ t: (key: string) => key }),
}));

const settings = {
  enabled: true,
  http_enabled: true,
  ws_enabled: true,
  oauth_enabled: true,
  fallback_to_direct: false,
  allow_proxy: true,
  base_url: "http://opencode-egress:12783",
  timeout_seconds: 120,
  secret_configured: true,
  runtime_override: false,
  sidecar_reachable: false,
};

function mountView() {
  return mount(OpenAIEgressSettings, {
    global: {
      stubs: {
        Icon: true,
        Toggle: {
          props: ["modelValue", "disabled"],
          emits: ["update:modelValue"],
          template: '<button type="button" class="toggle" :disabled="disabled" @click="$emit(\'update:modelValue\', !modelValue)">{{ modelValue }}</button>',
        },
      },
    },
  });
}

describe("OpenAIEgressSettings", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getSettings.mockResolvedValue({ ...settings });
    updateSettings.mockImplementation(async (payload) => ({ ...settings, ...payload, runtime_override: true }));
    testSettings.mockResolvedValue({
      ...settings,
      sidecar_reachable: true,
      sidecar_service: "sub2api-opencode-egress",
      sidecar_version: "1.18.20",
      sidecar_runtime: "bun",
    });
  });

  it("loads settings without displaying the shared secret", async () => {
    const wrapper = mountView();
    await flushPromises();

    expect(getSettings).toHaveBeenCalledOnce();
    expect(wrapper.text()).toContain("http://opencode-egress:12783");
    expect(wrapper.text()).toContain("admin.settings.openaiEgress.secretConfigured");
    expect(wrapper.text()).not.toContain("health-secret");
  });

  it("saves all operator-facing switches", async () => {
    const wrapper = mountView();
    await flushPromises();

    const toggles = wrapper.findAll("button.toggle");
    await toggles[4]!.trigger("click");
    const saveButton = wrapper.findAll("button").find((button) => button.text() === "common.save");
    expect(saveButton).toBeDefined();
    await saveButton!.trigger("click");
    await flushPromises();

    expect(updateSettings).toHaveBeenCalledWith({
      enabled: true,
      http_enabled: true,
      ws_enabled: true,
      oauth_enabled: true,
      fallback_to_direct: true,
      allow_proxy: true,
    });
    expect(testSettings).toHaveBeenCalledOnce();
    expect(wrapper.text()).toContain("admin.settings.openaiEgress.statusReady");
  });

  it("shows ready only after the compatibility health check passes", async () => {
    const wrapper = mountView();
    await flushPromises();

    const testButton = wrapper.findAll("button").find((button) =>
      button.text().includes("admin.settings.openaiEgress.test"),
    );
    expect(testButton).toBeDefined();
    await testButton!.trigger("click");
    await flushPromises();

    expect(testSettings).toHaveBeenCalledOnce();
    expect(wrapper.text()).toContain("admin.settings.openaiEgress.statusReady");
    expect(wrapper.text()).toContain("OpenCode 1.18.20");
  });
});
