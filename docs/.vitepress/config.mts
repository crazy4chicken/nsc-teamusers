import { defineConfig } from 'vitepress'
import { tabsMarkdownPlugin } from 'vitepress-plugin-tabs'

const base = '/nsc-teamusers/'

export default defineConfig({
  title: 'Teamusers',
  description: 'Standalone IAM microservice',
  base,
  cleanUrls: true,
  lastUpdated: true,
  markdown: {
    config(md) {
      md.use(tabsMarkdownPlugin)
    }
  },
  themeConfig: {
    nav: [
      { text: 'Guide', link: '/guide/getting-started' },
      { text: 'API Reference', link: '/api/overview' },
      {
        text: 'GitHub',
        link: 'https://github.com/crazy4chicken/nsc-teamusers'
      }
    ],
    sidebar: {
      '/guide/': [
        {
          text: 'Usage',
          items: [
            { text: 'Getting Started', link: '/guide/getting-started' },
            { text: 'Subject targeting', link: '/guide/subjects' },
            { text: 'Authentication Security', link: '/guide/security' },
            { text: 'Operations Runbook', link: '/guide/operations' },
            { text: 'REST pagination', link: '/guide/pagination' },
            { text: 'Administrative Permissions', link: '/guide/permissions' },
            { text: 'Nekostick Deployment', link: '/guide/nekostick' }
          ]
        },
        {
          text: 'Development',
          items: [
            { text: 'Permission keys', link: '/guide/permission-keys' },
            { text: 'SDK Usage', link: '/guide/sdks' },
            { text: 'API Docs Automation', link: '/guide/api-docs' }
          ]
        }
      ],
      '/api/': [
        {
          text: 'API Reference',
          items: [
            { text: 'Overview', link: '/api/overview' },
            {
              text: 'Reference',
              items: [
                { text: 'Authentication', link: '/api/reference/authentication' },
                { text: 'Self-service', link: '/api/reference/self-service' },
                { text: 'Users', link: '/api/reference/users' },
                { text: 'Teams', link: '/api/reference/teams' },
                { text: 'Groups', link: '/api/reference/groups' },
                { text: 'Roles', link: '/api/reference/roles' },
                { text: 'Permissions', link: '/api/reference/permissions' },
                { text: 'Policies', link: '/api/reference/policies' },
                { text: 'Keys', link: '/api/reference/keys' },
                { text: 'SCIM', link: '/api/reference/scim' },
                { text: 'Impersonation', link: '/api/reference/impersonation' },
                { text: 'Bindings', link: '/api/reference/bindings' },
                { text: 'Audit', link: '/api/reference/audit' },
                { text: 'Sessions', link: '/api/reference/sessions' },
                { text: 'Invitations', link: '/api/reference/invitations' },
                { text: 'Authorization', link: '/api/reference/authorization' },
                { text: 'Health', link: '/api/reference/health' }
              ]
            },
            { text: 'Download OpenAPI 3.1 specification', link: `${base}openapi.yaml` }
          ]
        }
      ]
    },
    search: {
      provider: 'local'
    }
  }
})
