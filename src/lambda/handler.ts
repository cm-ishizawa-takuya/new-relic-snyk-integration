import { Context, APIGatewayEvent, APIGatewayProxyResult } from 'aws-lambda'
import { Org, Project, ProjectGetResponseType } from 'snyk-api-ts-client/dist/client/generated/org'
import * as aws from 'aws-sdk'
import * as crypto from 'crypto'
import axios from 'axios'

type SnykProjectType = ProjectGetResponseType
type SnykIssueType = Exclude<Project.AggregatedissuesPostResponseType['issues'], undefined> extends (infer U)[] ? U : unknown

type SnykWebhookProjectSnapshotType = {
  project?: SnykProjectType
  newIssues: SnykIssueType[]
  removedIssues: SnykIssueType[]
}

type ProjectInfo = {
  projectName: string
  snykOrigin: string
  artifactURL: string
  disclosureUrl: string
  entityType: string
  entityLookupValue: string
  containerImage: string
  imageBaseImage: string
  imageId: string
  imagePlatform: string
  imageTag: string
  issueCountsBySeverityCritical: number
  issueCountsBySeverityHigh: number
  issueCountsBySeverityMedium: number
  issueCountsBySeverityLow: number
  issueInstanceKey: string
}

type IssueInfo = {
  title: string
  'cvss.score': number
  cvssScore: number
  issueId: string
  issueSeverity: string
  issueType: string
  issueVendorId: string
  message: string
  pkgName: string
  priorityScore: number
  'remediation.exists': boolean
  remediationExists: boolean
  remediationRecommendation: string
  severity: string
  snykIssueType: string
}

type NewRelicRequestType = {
  findings: ({
    source: 'Snyk'
  } & ProjectInfo & IssueInfo)[]
}


const SnykWebhookSecretParameterName = '/SnykIntegration/SNYK_WEBHOOK_SECRET'
const SnykOrganizationIdParameterName = '/SnykIntegration/SNYK_ORGANIZATION_ID'
const SnykApiKeyParameterName = '/SnykIntegration/SNYK_API_KEY'
const NewRelicSecurityUrlParameterName = '/SnykIntegration/NEW_RELIC_SECURITY_URL'
const NewRelicInsightsUrlParameterName = '/SnykIntegration/NEW_RELIC_INSIGHTS_URL'
const NewRelicLicenseKeyParameterName = '/SnykIntegration/NEW_RELIC_LICENSE_KEY'
const SnykProjectTableName = 'SnykProjects'

class SsmWrapper {
  private ssm: aws.SSM

  constructor() {
    this.ssm = new aws.SSM()
  }

  public async getParameter(key: string): Promise<string> {
    const response = await this.ssm.getParameter({ Name: key, WithDecryption: true }).promise()
    if (response.Parameter?.Value == null) {
      console.error(`[SSM Error] キー "${key}" の値が読み取れませんでした。`)
      throw Error
    }
    return response.Parameter.Value
  }
}

class TableWrapper {
  private client: aws.DynamoDB.DocumentClient
  private projectId: string

  constructor(projectId: string) {
    this.client = new aws.DynamoDB.DocumentClient({apiVersion: '2012-08-10'})
    this.projectId = projectId
  }

  public async exists(): Promise<boolean> {
    const result = await this.client.get({
      TableName: SnykProjectTableName,
      Key: { 'projectId' : this.projectId }
    }).promise()

    return result.Item !== undefined
  }

  public async record() {
    await this.client.put({
      TableName: SnykProjectTableName,
      Item: {
        'projectId' : this.projectId,
      }
    }).promise()
  }
}

function verifySignature(event: APIGatewayEvent, secret: string) {
  const hmac = crypto.createHmac('sha256', secret)
  hmac.update(event.body!, 'utf8')

  const signature = `sha256=${hmac.digest('hex')}`
  return signature === event.headers['x-hub-signature']
}

function getProjectInfo(snykProj: SnykProjectType): ProjectInfo {
  const projectName = snykProj.name ?? ''
  const snykOrigin = snykProj.origin ?? ''
  const disclosureUrl = snykProj.browseUrl ?? ''
  const imageBaseImage = snykProj.imageBaseImage ?? ''
  const imageId = snykProj.imageId ?? ''
  const imagePlatform = snykProj.imagePlatform ?? ''
  const imageTag = snykProj.imageTag ?? ''
  const issueCountsBySeverityCritical =
    snykProj.issueCountsBySeverity?.critical ?? 0
  const issueCountsBySeverityHigh =
    snykProj.issueCountsBySeverity?.high ?? 0
  const issueCountsBySeverityMedium =
    snykProj.issueCountsBySeverity?.medium ?? 0
  const issueCountsBySeverityLow =
    snykProj.issueCountsBySeverity?.low ?? 0

  const projectNameParts = projectName.split(':')
  const containerImage = projectName.length > 1 ? `${projectNameParts[1]}:${imageTag}` : projectName

  const entityType =
    snykOrigin == 'ecr' || snykOrigin == 'docker-hub' ? 'ContainerImage' : 'Repository'

  const idxRepoURLBranch = projectName.indexOf('(')
  const [artifactURL, entityLookupValue, issueInstanceKey] = (() => {
    if (snykOrigin === 'github') {
      if (idxRepoURLBranch >= 0) {
        const pkg = projectName.substring(idxRepoURLBranch + 1, projectName.length - 1)
        console.log(`package: ${pkg}`)
        const artifactURL = `https://github.com/${projectName.substring(0, idxRepoURLBranch)}`
        const entityLookupValue = artifactURL
        const issueInstanceKey = (snykProj.branch ?? '') != '' ?
          `${artifactURL}/blob/${snykProj.branch}/${pkg}` : artifactURL

        return [artifactURL, entityLookupValue, issueInstanceKey]
      } else {
        const artifactURL = `https://github.com/${projectNameParts[0]}`
        const entityLookupValue = artifactURL
        const issueInstanceKey = artifactURL

        return [artifactURL, entityLookupValue, issueInstanceKey]
      }
    } else if (snykOrigin === 'docker-hub') {
      const entityLookupValue = imageId
      if (idxRepoURLBranch >= 0) {
        const artifactURL = `https://hub.docker.com/repository/docker/${projectName.substring(0, idxRepoURLBranch)}`
        const issueInstanceKey = (snykProj.branch ?? '') != '' ?
          `${artifactURL}/tree/${snykProj.branch}` : artifactURL

        return [artifactURL, entityLookupValue, issueInstanceKey]
      } else {
        const artifactURL = `https://hub.docker.com/repository/docker/${projectNameParts[0]}`
        const issueInstanceKey = artifactURL
        
        return [artifactURL, entityLookupValue, issueInstanceKey]
      }
    } else if (snykOrigin === 'ecr') {
      const artifactURL = projectName
      const entityLookupValue = imageId
      const issueInstanceKey = artifactURL

      return [artifactURL, entityLookupValue, issueInstanceKey]
    } else if (snykOrigin === 'cli') {
      const artifactURL = snykProj.remoteRepoUrl ?? ''
      const entityLookupValue = artifactURL
      const issueInstanceKey = artifactURL

      return [artifactURL, entityLookupValue, issueInstanceKey]
    } else {
      console.error(`Invalid Origin: ${snykOrigin}`)
      throw Error
    }
  })()

  return {
    projectName,
    snykOrigin,
    artifactURL,
    disclosureUrl,
    entityType,
    entityLookupValue,
    containerImage,
    imageBaseImage,
    imageId,
    imagePlatform,
    imageTag,
    issueCountsBySeverityCritical,
    issueCountsBySeverityHigh,
    issueCountsBySeverityMedium,
    issueCountsBySeverityLow,
    issueInstanceKey,
  }
}

function getIssueInfo(snykIssue: SnykIssueType): IssueInfo {
  const data = snykIssue.issueData

  const title = data.title
  const cvssScore = data.cvssScore
  const issueId = (data.identifiers?.CVE?.length ?? 0) > 0 ?
    data.identifiers!.CVE![0] : data.id
  const issueSeverity = data.severity
  const issueType = 'Library Vulnerability'
  const issueVendorId = issueId
  const message = data.description
  const pkgName = snykIssue.pkgName
  const priorityScore = snykIssue.priority?.score ?? 0
  const remediationExists = snykIssue.fixInfo?.isFixable ?? false
  const remediationRecommendation = remediationExists ?
    `upgrade ${pkgName} to ${snykIssue.fixInfo?.fixedIn![0]}` : ''
  const severity = issueSeverity.toUpperCase()
  const snykIssueType = snykIssue.issueType

  return {
    title,
    'cvss.score': cvssScore,
    cvssScore,
    issueId,
    issueSeverity,
    issueType,
    issueVendorId,
    message,
    pkgName,
    priorityScore,
    'remediation.exists': remediationExists,
    remediationExists,
    remediationRecommendation,
    severity,
    snykIssueType,
  }
}

function makeRequest(projectInfo: ProjectInfo, issuesInfo: IssueInfo[]): NewRelicRequestType {
  return {
    findings: issuesInfo.map((issueInfo) => {
      return {
        source: 'Snyk',
        ...projectInfo,
        ...issueInfo,
      }
    })
  }
}

async function getSnykAggregatedIssues(projectId: string, ssm: SsmWrapper): Promise<SnykIssueType[]> {
  const orgId = await ssm.getParameter(SnykOrganizationIdParameterName)
  const url = `https://api.snyk.io/api/v1/org/${orgId}/project/${projectId}/aggregated-issues`
  const apiKey = await ssm.getParameter(SnykApiKeyParameterName)
  

  const headers = {
    'Content-Type': 'application/json',
    'Authorization': `token ${apiKey}`
  }
  const body = {
    "includeDescription": true,
  }

  const response = await axios.post(url, body, { headers })

  return response.data.issues as SnykIssueType[]
}

async function postNewRelicSecurityData(requestBody: NewRelicRequestType, ssm: SsmWrapper): Promise<any> {
  const url = await ssm.getParameter(NewRelicSecurityUrlParameterName)
  const apiKey = await ssm.getParameter(NewRelicLicenseKeyParameterName)

  const headers = {
    'Content-Type': 'application/json',
    'Api-Key': apiKey,
  }

  const response = await axios.post(url, requestBody, { headers })

  return response
}

async function postNewRelicErrorNotification(error: unknown, ssm: SsmWrapper): Promise<any> {
  const url = await ssm.getParameter(NewRelicInsightsUrlParameterName)
  const apiKey = await ssm.getParameter(NewRelicLicenseKeyParameterName)

  const headers = {
    'Content-Type': 'application/json',
    'Api-Key': apiKey,
  }

  const body = {
    eventType: 'SnykFindingsErrors',
    message: `${error}`
  }

  const response = await axios.post(url, body, { headers })

  return response
}

export const handler = async (event: APIGatewayEvent, context: Context): Promise<APIGatewayProxyResult> => {
  console.log('NodeJs HTTP trigger function processed a request.')
  if (event.body === null) {
    return {
      statusCode: 400,
      body: JSON.stringify('Bad request'),
    }
  }
  
  const ssm = new SsmWrapper()

  try {
    const secret = await ssm.getParameter(SnykWebhookSecretParameterName)
    if (!verifySignature(event, secret)) {
      console.error('Integrity of request compromised, aborting')
      return {
        statusCode: 403,
        body: JSON.stringify('Unauthorized'),
      }
    }

    const data = JSON.parse(event.body) as SnykWebhookProjectSnapshotType
    if (data.project === undefined) {
      console.log('No project found!')
      return {
        statusCode: 200,
        body: JSON.stringify('No project found!'),
      }
    } else {
      console.log(`${data.project.name}, data.newIssues.length: ${data.newIssues.length}`)
      const projectInfo = getProjectInfo(data.project)
      const projectId = data.project.id ?? ''
      const table = new TableWrapper(projectId)
      const isNewProject = !(await table.exists())
      let issuesInfo: IssueInfo[]

      if (isNewProject) {
        console.log(`${projectId} had not found.`)
        const aggregatedIssues = await getSnykAggregatedIssues(projectId, ssm)
        issuesInfo = aggregatedIssues.map((issue) => getIssueInfo(issue)) ?? []
      } else {
        console.log(`${projectId} has found.`)
        issuesInfo = data.newIssues.map((issue) => getIssueInfo(issue))
      }
      const newRelicPostRequestBody = makeRequest(projectInfo, issuesInfo)

      if (newRelicPostRequestBody.findings.length === 0) {
        return {
          statusCode: 200,
          body: JSON.stringify('No valid payload received!'),
        }
      }

      const response = await postNewRelicSecurityData(newRelicPostRequestBody, ssm)

      if (response.status !== 200 || ('success' in response.data && !response.data.success)) {
        return {
          statusCode: 400,
          body: JSON.stringify('Bad Request'),
        }
      }

      if (isNewProject) {
        console.log(`Record ${projectId}`)
        await table.record()
      }

      return {
        statusCode: 200,
        body: JSON.stringify('Succeeded!')
      }
    }
  } catch(e) {
    console.error(`Error：${e}`)

    const result = await postNewRelicErrorNotification(e, ssm)
    console.log(`StatusCode: ${result.status}`)

    return {
      statusCode: 400,
      body: JSON.stringify('Bad request'),
    }
  }
}
