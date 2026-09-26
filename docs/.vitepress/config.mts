import { defineConfig } from 'vitepress'

export default defineConfig({
  title: 'Teamusers',
  description: 'Standalone IAM microservice',
  cleanUrls: true,
  lastUpdated: true,
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
          text: 'Guide',
          items: [
            { text: 'Getting Started', link: '/guide/getting-started' },
            { text: 'Authentication Security', link: '/guide/security' },
            { text: 'Operations Runbook', link: '/guide/operations' },
            { text: 'Administrative Permissions', link: '/guide/permissions' },
            { text: 'Nekostick Deployment', link: '/guide/nekostick' }
          ]
        }
      ],
      '/api/': [
        {
          text: 'API Reference',
          items: [
            { text: 'Overview', link: '/api/overview' },
            { text: 'Authentication', link: '/api/authentication' },
            { text: 'Users', link: '/api/users' },
            { text: 'Teams', link: '/api/teams' },
            { text: 'Groups', link: '/api/groups' },
            { text: 'Roles', link: '/api/roles' },
            { text: 'Permissions', link: '/api/permissions' },
            { text: 'Bindings', link: '/api/bindings' },
            { text: 'Audit', link: '/api/audit' },
            { text: 'Sessions', link: '/api/sessions' },
            { text: 'Self-service', link: '/api/self-service' },
            { text: 'Invitations', link: '/api/invitations' },
            { text: 'Download OpenAPI 3.1 specification', link: '/openapi.yaml' }
          ]
        }
      ]
    },
    search: {
      provider: 'local'
    }
  }
})
