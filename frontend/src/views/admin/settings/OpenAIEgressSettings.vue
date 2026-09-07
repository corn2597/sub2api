<template>
  <section class="card overflow-hidden">
    <div class="border-b border-gray-100 px-6 py-4 dark:border-dark-700">
      <div class="flex flex-wrap items-start justify-between gap-4">
        <div>
          <div class="flex items-center gap-2">
            <span class="flex h-8 w-8 items-center justify-center rounded-lg bg-primary-50 text-primary-600 dark:bg-primary-900/30 dark:text-primary-300">
              <Icon name="server" size="sm" />
            </span>
            <h2 class="text-lg font-semibold text-gray-900 dark:text-white">
              {{ t("admin.settings.openaiEgress.title") }}
            </h2>
          </div>
          <p class="mt-2 max-w-3xl text-sm text-gray-500 dark:text-gray-400">
            {{ t("admin.settings.openaiEgress.description") }}
          </p>
        </div>
        <div
          class="inline-flex items-center gap-2 rounded-full px-3 py-1.5 text-xs font-medium"
          :class="statusClass"
        >
          <span class="h-2 w-2 rounded-full" :class="statusDotClass" />
          {{ statusLabel }}
        </div>
      </div>
    </div>

    <div class="space-y-5 p-6">
      <div
        v-if="loading"
        class="flex items-center gap-2 text-sm text-gray-500 dark:text-gray-400"
      >
        <span class="h-4 w-4 animate-spin rounded-full border-b-2 border-primary-600" />
        {{ t("common.loading") }}
      </div>

      <template v-else>
        <div
          class="flex items-start justify-between gap-4 rounded-lg border border-gray-200 p-4 dark:border-dark-600"
        >
          <div>
            <div class="font-medium text-gray-900 dark:text-white">
              {{ t("admin.settings.openaiEgress.enabled") }}
            </div>
            <p class="mt-1 text-sm text-gray-500 dark:text-gray-400">
              {{ t("admin.settings.openaiEgress.enabledHint") }}
            </p>
          </div>
          <Toggle v-model="form.enabled" />
        </div>

        <div class="grid gap-3 md:grid-cols-3">
          <label
            v-for="item in channels"
            :key="item.key"
            class="flex items-center justify-between gap-3 rounded-lg border border-gray-200 px-4 py-3 dark:border-dark-600"
          >
            <span>
              <span class="block text-sm font-medium text-gray-800 dark:text-gray-100">{{ item.label }}</span>
              <span class="mt-0.5 block text-xs text-gray-500 dark:text-gray-400">{{ item.hint }}</span>
            </span>
            <Toggle v-model="form[item.key]" :disabled="!form.enabled" />
          </label>
        </div>

        <div class="flex items-start justify-between gap-4 rounded-lg border border-gray-200 p-4 dark:border-dark-600">
          <div>
            <div class="font-medium text-gray-900 dark:text-white">
              {{ t("admin.settings.openaiEgress.fallback") }}
            </div>
            <p class="mt-1 text-sm text-gray-500 dark:text-gray-400">
              {{ t("admin.settings.openaiEgress.fallbackHint") }}
            </p>
          </div>
          <Toggle v-model="form.fallback_to_direct" />
        </div>

        <div class="flex items-start justify-between gap-4 rounded-lg border border-gray-200 p-4 dark:border-dark-600">
          <div>
            <div class="font-medium text-gray-900 dark:text-white">
              {{ t("admin.settings.openaiEgress.allowProxy") }}
            </div>
            <p class="mt-1 text-sm text-gray-500 dark:text-gray-400">
              {{ t("admin.settings.openaiEgress.allowProxyHint") }}
            </p>
          </div>
          <Toggle v-model="form.allow_proxy" :disabled="!form.enabled" />
        </div>

        <div class="grid gap-4 md:grid-cols-2">
          <div class="rounded-lg bg-gray-50 p-4 dark:bg-dark-800/70">
            <div class="text-xs font-medium uppercase tracking-wide text-gray-500 dark:text-gray-400">
              {{ t("admin.settings.openaiEgress.endpoint") }}
            </div>
            <code class="mt-2 block break-all font-mono text-sm text-gray-800 dark:text-gray-100">
              {{ settings?.base_url || "-" }}
            </code>
            <p class="mt-2 text-xs text-gray-500 dark:text-gray-400">
              {{ t("admin.settings.openaiEgress.endpointHint") }}
            </p>
          </div>
          <div class="rounded-lg bg-gray-50 p-4 dark:bg-dark-800/70">
            <div class="text-xs font-medium uppercase tracking-wide text-gray-500 dark:text-gray-400">
              {{ t("admin.settings.openaiEgress.security") }}
            </div>
            <div class="mt-2 flex items-center gap-2 text-sm text-gray-800 dark:text-gray-100">
              <Icon :name="settings?.secret_configured ? 'checkCircle' : 'exclamationTriangle'" size="sm" :class="settings?.secret_configured ? 'text-emerald-500' : 'text-amber-500'" />
              {{ settings?.secret_configured ? t("admin.settings.openaiEgress.secretConfigured") : t("admin.settings.openaiEgress.secretMissing") }}
            </div>
            <p class="mt-2 text-xs text-gray-500 dark:text-gray-400">
              {{ t("admin.settings.openaiEgress.securityHint") }}
            </p>
          </div>
        </div>

        <div
          v-if="form.enabled && form.fallback_to_direct"
          class="flex items-start gap-3 rounded-lg border border-amber-200 bg-amber-50 p-4 dark:border-amber-800/60 dark:bg-amber-900/20"
        >
          <Icon name="infoCircle" size="sm" class="mt-0.5 flex-shrink-0 text-amber-600 dark:text-amber-400" />
          <p class="text-sm text-amber-800 dark:text-amber-200">
            {{ t("admin.settings.openaiEgress.fallbackNotice") }}
          </p>
        </div>

        <div
          v-if="form.enabled && !form.allow_proxy"
          class="flex items-start gap-3 rounded-lg border border-amber-200 bg-amber-50 p-4 dark:border-amber-800/60 dark:bg-amber-900/20"
        >
          <Icon name="infoCircle" size="sm" class="mt-0.5 flex-shrink-0 text-amber-600 dark:text-amber-400" />
          <p class="text-sm text-amber-800 dark:text-amber-200">
            {{ t("admin.settings.openaiEgress.proxyDisabledNotice") }}
          </p>
        </div>

        <div class="flex flex-wrap items-center justify-between gap-3 border-t border-gray-100 pt-4 dark:border-dark-700">
          <div class="text-xs text-gray-500 dark:text-gray-400">
            <span v-if="settings?.sidecar_version">{{ settings.sidecar_service }} · OpenCode {{ settings.sidecar_version }}</span>
            <span v-else>{{ t("admin.settings.openaiEgress.notChecked") }}</span>
            <span v-if="settings?.timeout_seconds"> · {{ settings.timeout_seconds }}s timeout</span>
          </div>
          <div class="flex gap-2">
            <button type="button" class="btn btn-secondary btn-sm inline-flex items-center gap-1.5" :disabled="testing" @click="testSidecar">
              <Icon name="refresh" size="xs" :class="testing && 'animate-spin'" />
              {{ t("admin.settings.openaiEgress.test") }}
            </button>
            <button type="button" class="btn btn-primary btn-sm" :disabled="saving" @click="save">
              {{ saving ? t("common.saving") : t("common.save") }}
            </button>
          </div>
        </div>

        <p v-if="errorMessage" class="text-sm text-red-600 dark:text-red-400">{{ errorMessage }}</p>
        <p v-if="settings?.sidecar_error" class="text-sm text-amber-700 dark:text-amber-300">{{ settings.sidecar_error }}</p>
      </template>
    </div>
  </section>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from "vue";
import { useI18n } from "vue-i18n";
import { adminAPI } from "@/api";
import type { OpenAIEgressSettings } from "@/api/admin/settings";
import Icon from "@/components/icons/Icon.vue";
import Toggle from "@/components/common/Toggle.vue";
import { useAppStore } from "@/stores";

const { t } = useI18n();
const appStore = useAppStore();
const loading = ref(true);
const saving = ref(false);
const testing = ref(false);
const errorMessage = ref("");
const settings = ref<OpenAIEgressSettings | null>(null);
const form = reactive({
  enabled: false,
  http_enabled: true,
  ws_enabled: true,
  oauth_enabled: true,
  fallback_to_direct: false,
  allow_proxy: true,
});

const channels = computed(() => [
  { key: "http_enabled" as const, label: t("admin.settings.openaiEgress.http"), hint: t("admin.settings.openaiEgress.httpHint") },
  { key: "ws_enabled" as const, label: t("admin.settings.openaiEgress.ws"), hint: t("admin.settings.openaiEgress.wsHint") },
  { key: "oauth_enabled" as const, label: t("admin.settings.openaiEgress.oauth"), hint: t("admin.settings.openaiEgress.oauthHint") },
]);

const statusLabel = computed(() => {
  if (!settings.value?.enabled) return t("admin.settings.openaiEgress.statusDisabled");
  if (settings.value.sidecar_reachable) return t("admin.settings.openaiEgress.statusReady");
  return t("admin.settings.openaiEgress.statusUnavailable");
});
const statusClass = computed(() => {
  if (!settings.value?.enabled) return "bg-gray-100 text-gray-600 dark:bg-dark-700 dark:text-gray-300";
  return settings.value.sidecar_reachable
    ? "bg-emerald-50 text-emerald-700 dark:bg-emerald-900/20 dark:text-emerald-300"
    : "bg-amber-50 text-amber-700 dark:bg-amber-900/20 dark:text-amber-300";
});
const statusDotClass = computed(() => {
  if (!settings.value?.enabled) return "bg-gray-400";
  return settings.value.sidecar_reachable ? "bg-emerald-500" : "bg-amber-500";
});

function applySettings(value: OpenAIEgressSettings) {
  settings.value = value;
  form.enabled = value.enabled;
  form.http_enabled = value.http_enabled;
  form.ws_enabled = value.ws_enabled;
  form.oauth_enabled = value.oauth_enabled;
  form.fallback_to_direct = value.fallback_to_direct;
  form.allow_proxy = value.allow_proxy;
}

async function load() {
  loading.value = true;
  errorMessage.value = "";
  try {
    applySettings(await adminAPI.settings.getOpenAIEgressSettings());
  } catch (error) {
    errorMessage.value = String(error);
  } finally {
    loading.value = false;
  }
}

async function save() {
  saving.value = true;
  errorMessage.value = "";
  try {
    const updated = await adminAPI.settings.updateOpenAIEgressSettings({ ...form });
    applySettings(updated);
    if (updated.enabled) {
      applySettings(await adminAPI.settings.testOpenAIEgressSettings());
    }
    appStore.showSuccess(t("admin.settings.openaiEgress.saved"));
  } catch (error) {
    errorMessage.value = String(error);
  } finally {
    saving.value = false;
  }
}

async function testSidecar() {
  testing.value = true;
  errorMessage.value = "";
  try {
    const updated = await adminAPI.settings.testOpenAIEgressSettings();
    applySettings(updated);
    if (updated.sidecar_reachable) appStore.showSuccess(t("admin.settings.openaiEgress.testPassed"));
  } catch (error) {
    errorMessage.value = String(error);
  } finally {
    testing.value = false;
  }
}

onMounted(load);
</script>
