import * as cdk from 'aws-cdk-lib'
import * as iam from 'aws-cdk-lib/aws-iam'
import * as ssm from 'aws-cdk-lib/aws-ssm'
import * as apigw from 'aws-cdk-lib/aws-apigateway'
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb'
import { NodejsFunction } from 'aws-cdk-lib/aws-lambda-nodejs'
import { Construct } from 'constructs'
import { Duration } from 'aws-cdk-lib'

export class NewRelicSnykIntegrationStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props)

    const role = new iam.Role(this, 'Role', {
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
    })
    role.addManagedPolicy(iam.ManagedPolicy.fromAwsManagedPolicyName('service-role/AWSLambdaBasicExecutionRole'))

    const lambda = new NodejsFunction(this, 'LambdaFunction', {
      entry: 'src/lambda/handler.ts',
      role,
      bundling: {
        nodeModules: [
          'axios',
          'snyk-api-ts-client',
        ]
      },
      timeout: Duration.seconds(60),
    })

    const snykWebhookSecretParam = ssm.StringParameter.fromSecureStringParameterAttributes(this, 'webhookSecretParam', {
      parameterName: '/SnykIntegration/SNYK_WEBHOOK_SECRET',
    })
    const snykOrganizationParam = ssm.StringParameter.fromSecureStringParameterAttributes(this, 'organizationParam', {
      parameterName: '/SnykIntegration/SNYK_ORGANIZATION_ID',
    })
    const snykApiKeyParam = ssm.StringParameter.fromSecureStringParameterAttributes(this, 'snykApiKeyParam', {
      parameterName: '/SnykIntegration/SNYK_API_KEY',
    })
    const newRelicSecurityUrlParam = new ssm.StringParameter(this, 'newRelicSecurityUrl', {
      parameterName: '/SnykIntegration/NEW_RELIC_SECURITY_URL',
      stringValue: 'https://security-api.newrelic.com/security/v1',
    })
    const newRelicInsightsUrlParam = ssm.StringParameter.fromSecureStringParameterAttributes(this, 'newRelicInsightsUrl', {
      parameterName: '/SnykIntegration/NEW_RELIC_INSIGHTS_URL',
    })
    const newRelicLicenseKeyParam = ssm.StringParameter.fromSecureStringParameterAttributes(this, 'newRelicLicenseKey', {
      parameterName: '/SnykIntegration/NEW_RELIC_LICENSE_KEY',
    })
    snykWebhookSecretParam.grantRead(role)
    snykOrganizationParam.grantRead(role)
    snykApiKeyParam.grantRead(role)
    newRelicSecurityUrlParam.grantRead(role)
    newRelicInsightsUrlParam.grantRead(role)
    newRelicLicenseKeyParam.grantRead(role)

    const table = new dynamodb.Table(this, 'SnykProjectTable', {
      tableName: 'SnykProjects',
      partitionKey: { name: 'projectId', type: dynamodb.AttributeType.STRING },
    })
    table.applyRemovalPolicy(cdk.RemovalPolicy.DESTROY)
    table.grantReadWriteData(role)

    const api = new apigw.LambdaRestApi(this, 'Gateway', {
      handler: lambda,
      proxy: false,
    })

    const snykToNewRelic = api.root.addResource('snykToNewRelic')
    snykToNewRelic.addMethod('POST')
  }
}
