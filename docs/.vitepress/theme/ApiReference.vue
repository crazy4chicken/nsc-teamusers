<script setup lang="ts">
import { computed, onMounted, shallowRef } from 'vue'
import { useData } from 'vitepress'

type ScalarApiReference = typeof import('@scalar/api-reference')['ApiReference']

const props = defineProps<{
  spec: string
}>()
const { isDark } = useData()
const scalarApiReference = shallowRef<ScalarApiReference | null>(null)
const configuration = computed(() => ({
  url: props.spec,
  darkMode: isDark.value,
  hideDownloadButton: false
}))

onMounted(async () => {
  const [{ ApiReference }] = await Promise.all([
    import('@scalar/api-reference'),
    import('@scalar/api-reference/style.css')
  ])
  scalarApiReference.value = ApiReference
})
</script>

<template>
  <ClientOnly>
    <component
      :is="scalarApiReference"
      v-if="scalarApiReference"
      :configuration="configuration"
    />
  </ClientOnly>
</template>
