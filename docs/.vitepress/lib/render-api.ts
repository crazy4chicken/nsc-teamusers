import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { parse } from 'yaml'

type RecordValue = Record<string, unknown>

type ApiOperation = RecordValue & {
  tags?: unknown
  summary?: unknown
  description?: unknown
  requestBody?: unknown
  responses?: unknown
}

type ApiRoute = {
  path: string
  method: string
  operation: ApiOperation
}

type ApiReferencePath = {
  params: {
    tag: string
    title: string
  }
  content: string
}

const HTTP_METHODS: Record<string, true> = {
  delete: true,
  get: true,
  head: true,
  options: true,
  patch: true,
  post: true,
  put: true,
  trace: true
}

function compareStrings(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0
}

export function renderApiReferencePaths(): ApiReferencePath[] {
  const document = parse(
    readFileSync(resolve(process.cwd(), 'docs/public/openapi.yaml'), 'utf8')
  ) as RecordValue
  const routesByTag = new Map<string, ApiRoute[]>()
  const paths = asRecord(document.paths)

  for (const path of Object.keys(paths).sort()) {
    const pathItem = asRecord(paths[path])
    for (const method of Object.keys(pathItem)
      .filter((candidate) => HTTP_METHODS[candidate.toLowerCase()] === true)
      .sort(compareStrings)) {
      const operation = asRecord(pathItem[method]) as ApiOperation
      for (const tag of operationTags(operation)) {
        const routes = routesByTag.get(tag) ?? []
        routes.push({ path, method, operation })
        routesByTag.set(tag, routes)
      }
    }
  }

  return [...routesByTag.keys()]
    .sort(compareStrings)
    .map((tag) => ({
      params: {
        tag: tag.toLowerCase(),
        title: `${tag} API Reference`
      },
      content: renderTag(tag, routesByTag.get(tag) ?? [])
    }))
}

function operationTags(operation: ApiOperation): string[] {
  if (!Array.isArray(operation.tags)) {
    return []
  }
  return operation.tags.filter((tag): tag is string => typeof tag === 'string')
}

function renderTag(tag: string, routes: ApiRoute[]): string {
  const sortedRoutes = [...routes].sort((left, right) => {
    if (left.path !== right.path) {
      return compareStrings(left.path, right.path)
    }
    return compareStrings(left.method, right.method)
  })
  const lines = [`# ${tag} API Reference`, '']
  for (const route of sortedRoutes) {
    renderOperation(lines, route)
  }
  return lines.join('\n')
}

function renderOperation(lines: string[], route: ApiRoute): void {
  const operation = route.operation
  lines.push(`## <span class="http-method http-${route.method.toLowerCase()}">${route.method.toUpperCase()}</span> ${headingPath(route.path)}`, '')
  if (typeof operation.summary === 'string' && operation.summary !== '') {
    lines.push(operation.summary, '')
  }
  if (typeof operation.description === 'string' && operation.description !== '') {
    lines.push(operation.description, '')
  }

  const parameters = pathParameters(route.path)
  if (parameters.length > 0) {
    lines.push(
      '### Path parameters',
      '',
      '| Parameter | Description |',
      '| --- | --- |',
      ...parameters.map((parameter) => `| ${tableCell(parameter)} | Path parameter. |`),
      ''
    )
  }

  const request = asRecord(operation.requestBody)
  const requestBody = mediaType(asRecord(request.content), 'application/json')
  if (requestBody !== undefined) {
    renderRequest(lines, requestBody)
  }

  const responses = asRecord(operation.responses)
  renderResponses(lines, responses)
  renderErrors(lines, responses)
}

function renderRequest(lines: string[], requestBody: RecordValue): void {
  const schema = asRecord(requestBody.schema)
  const properties = asRecord(schema.properties)
  const required = new Set(
    Array.isArray(schema.required)
      ? schema.required.filter((field): field is string => typeof field === 'string')
      : []
  )
  lines.push(
    '### Request body (application/json)',
    '',
    '| Field | Type | Required |',
    '| --- | --- | --- |'
  )
  for (const field of Object.keys(properties).sort()) {
    lines.push(
      `| ${tableCell(field)} | ${tableCell(schemaType(properties[field]))} | ${required.has(field) ? 'Yes' : 'No'} |`
    )
  }
  lines.push('')
  if (Object.prototype.hasOwnProperty.call(requestBody, 'example')) {
    renderJSON(lines, requestBody.example)
  }
}

function renderResponses(lines: string[], responses: RecordValue): void {
  const success = responseEntries(responses).find(({ status }) => status >= 200 && status < 300)
  if (success === undefined) {
    return
  }
  lines.push('### Responses', '', `- **${success.key}** — ${success.description}`)
  const content = mediaType(asRecord(success.response.content), 'application/json')
  if (content !== undefined && Object.prototype.hasOwnProperty.call(content, 'example')) {
    renderJSON(lines, content.example)
  }
  lines.push('')
}

function renderErrors(lines: string[], responses: RecordValue): void {
  const errors = responseEntries(responses).filter(({ status }) => status < 200 || status >= 300)
  if (errors.length === 0) {
    return
  }
  lines.push(
    '### Errors',
    '',
    '| Status | Code | Detail |',
    '| --- | --- | --- |'
  )
  for (const error of errors) {
    const content = mediaType(asRecord(error.response.content), 'application/problem+json')
    const examples = problemExamples(content)
    if (examples.length === 0) {
      lines.push(`| ${error.key} |  | ${tableCell(error.description)} |`)
      continue
    }
    for (const example of examples) {
      lines.push(
        `| ${error.key} | ${tableCell(example.code)} | ${tableCell(error.description)} |`
      )
    }
  }
  lines.push('')
}

function responseEntries(responses: RecordValue): Array<{
  key: string
  status: number
  description: string
  response: RecordValue
}> {
  return Object.keys(responses)
    .map((key) => ({
      key,
      status: Number(key),
      response: asRecord(responses[key]),
      description: responseDescription(responses[key])
    }))
    .filter(({ status }) => Number.isFinite(status))
    .sort((left, right) => left.status - right.status)
}

function responseDescription(response: unknown): string {
  const description = asRecord(response).description
  return typeof description === 'string' ? description : ''
}

function problemExamples(content: RecordValue | undefined): Array<{ code: string }> {
  if (content === undefined) {
    return []
  }
  if (Object.prototype.hasOwnProperty.call(content, 'example')) {
    return [{ code: problemCode(content.example) }]
  }
  const examples = asRecord(content.examples)
  return Object.keys(examples)
    .sort(compareStrings)
    .map((name) => ({ code: problemCode(asRecord(examples[name]).value) }))
}

function problemCode(example: unknown): string {
  const detail = asRecord(example).detail
  return detail === undefined || detail === null ? '' : String(detail)
}

function mediaType(value: RecordValue | undefined, mediaTypeName: string): RecordValue | undefined {
  if (value === undefined) {
    return undefined
  }
  const mediaType = value[mediaTypeName]
  return mediaType === undefined ? undefined : asRecord(mediaType)
}

function pathParameters(path: string): string[] {
  const parameters: string[] = []
  const seen = new Set<string>()
  const pattern = /\{([^}]+)\}/g
  for (const match of path.matchAll(pattern)) {
    const name = match[1]
    if (!seen.has(name)) {
      seen.add(name)
      parameters.push(name)
    }
  }
  return parameters
}

function headingPath(path: string): string {
  return path.replaceAll('{', '\\{').replaceAll('}', '\\}')
}

function schemaType(schema: unknown): string {
  const value = asRecord(schema)
  const type = value.type
  if (type === 'array') {
    return `array<${schemaType(value.items)}>`
  }
  if (typeof type === 'string') {
    const format = value.format
    return typeof format === 'string' && format !== '' ? `${type} (${format})` : type === 'object' ? 'object' : type
  }
  const variants = Array.isArray(value.anyOf) ? value.anyOf : []
  for (const variant of variants) {
    const variantType = schemaType(variant)
    if (variantType !== 'object') {
      return variantType
    }
  }
  return 'object'
}

function renderJSON(lines: string[], value: unknown): void {
  lines.push('```json', JSON.stringify(value, null, 2) ?? 'null', '```', '')
}

function tableCell(value: string): string {
  return value
    .replaceAll('|', '\\|')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll(/\r?\n/g, ' ')
}

function asRecord(value: unknown): RecordValue {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? (value as RecordValue) : {}
}
