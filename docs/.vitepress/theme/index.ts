import DefaultTheme from 'vitepress/theme'
import ApiReference from './ApiReference.vue'

export default {
  extends: DefaultTheme,
  enhanceApp({ app }) {
    app.component('ApiReference', ApiReference)
  }
}
