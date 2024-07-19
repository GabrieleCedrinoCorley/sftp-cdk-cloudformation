import os
from aws_cdk import (
    CfnOutput,
    CfnTag,
    NestedStack,
    RemovalPolicy,
    Tags,
    Aws,
    aws_s3 as s3,
    aws_s3_notifications as s3n,
    aws_lambda as lambda_,
    aws_sns as sns,
    aws_iam as iam,
    aws_ec2 as ec2,
    Duration as Duration,
    aws_kms as kms,
    aws_logs as logs,
    aws_transfer as transfer,
    Fn
)
from constructs import Construct
from ego_cdk import (
    Stage,
)

class SFTP(NestedStack):

    def __init__(self, scope: Construct, construct_id: str, vpc: ec2.Vpc,stage: Stage, project_name: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        
        # dev etrm
        log_retention = logs.RetentionDays.ONE_MONTH
        log_encryption_key = "arn:aws:kms:eu-west-1:151425774723:key/a9c04dea-911c-4763-a361-e99cfee45268"  #ego/logs
        lambda_env_enc_key = "arn:aws:kms:eu-west-1:151425774723:key/f9f5cfbb-2ff1-4a2e-be43-b9d304e0b535"  #ego/lambda
        sns_encryption_key = "arn:aws:kms:eu-west-1:151425774723:key/86cc2c29-b411-4414-944d-3c7d0a38864b"  #ego/sns
        bucket_key = "arn:aws:kms:eu-west-1:151425774723:key/94348371-80a6-4d96-bb90-54b8dd60cc30"  #aws/s3

        # staging
        # log_retention = logs.RetentionDays.ONE_MONTH
        # log_encryption_key = "arn:aws:kms:eu-west-1:968863837277:key/16ba2107-5191-4a25-87b4-ffd2f4a495e0"  #ego/logs
        # lambda_env_enc_key = "arn:aws:kms:eu-west-1:968863837277:key/6c7e8a01-d652-449d-8152-eb39283824ad"  #ego/lambda
        # sns_encryption_key = "arn:aws:kms:eu-west-1:968863837277:key/041a48e0-e42f-4423-9681-0baf0a4c03a8"  #ego/sns
        # bucket_key = "arn:aws:kms:eu-west-1:968863837277:key/b3867507-6427-40fb-b330-1fb6094613eb"  #aws/s3


        #SFTP elastic ips, 2 for HA
        EIPTran01 = ec2.CfnEIP(
            self, "EIPTran01",
            domain="vpc"  
        )
        EIPTran02 = ec2.CfnEIP(
            self, "EIPTran02",
            domain="vpc"  
        )

        ################
        #    LAMBDA    #
        ################

        LambdaSFTPLogGroup = logs.LogGroup(
            self, "LambdaSFTPLogGroup",
            log_group_name="sftp-server-auth-lambda-logs",
            encryption_key=kms.Key.from_key_arn(
                self, 
                "LambdaLogGroupEncryptionKey", 
                log_encryption_key
            ),
            retention=log_retention
        )

        usersSecretManagerArn = f"arn:aws:secretsmanager:{Aws.REGION}:{Aws.ACCOUNT_ID}:secret:SFTP/*"
        SftpLambdaRole = iam.Role(self, "SftpLambdaRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaBasicExecutionRole")
            ],
            inline_policies={
                "TransferLoggingAccess": iam.PolicyDocument(
                    statements=[
                        iam.PolicyStatement(
                            effect=iam.Effect.ALLOW,
                            actions=[
                                "secretsmanager:GetSecretValue"
                            ],
                            resources=[usersSecretManagerArn]
                        )
                    ]
                )
            },
            role_name="sftp-lambda-role"
        )

        GetUserConfigLambda = lambda_.Function(self, "GetUserConfigLambda",
            environment_encryption=kms.Key.from_key_arn(
                self, 
                "EnvLambdaEncryptionKey", 
                lambda_env_enc_key
            ),
            log_group=LambdaSFTPLogGroup,
            description="Lookup and return user data from AWS Secrets Manager.",
            handler="lambda_code.lambda_handler",
            role=SftpLambdaRole,
            runtime=lambda_.Runtime.PYTHON_3_12,
            environment={
                "SecretsManagerRegion": Aws.REGION
            },
            code=lambda_.Code.from_asset(os.path.join(os.getcwd(), "aws_tool_transfer_family_cdk/lambda_code"))  
        )


        ####################
        #    SFT SERVER    #
        ####################

        SFTPServerLogGroup = logs.LogGroup(
            self, "SFTPServerLogGroup",
            log_group_name="transferfamily-sftp-logs",
            encryption_key=kms.Key.from_key_arn(
                self, 
                "SFTPLogGroupEncryptionKey", 
                log_encryption_key
            ),
            retention=log_retention
        )

        self.TransferServerRole = iam.Role(self, "TransferServerRole",
            assumed_by=iam.ServicePrincipal("transfer.amazonaws.com"),
            inline_policies={
                "TransferLoggingAccess": iam.PolicyDocument(
                    statements=[
                        iam.PolicyStatement(
                            effect=iam.Effect.ALLOW,
                            actions=[
                                "logs:CreateLogStream",
                                "logs:PutLogEvents"
                            ],
                            resources=[SFTPServerLogGroup.log_group_arn]
                        )
                    ]
                )
            },
            role_name="sftp-server-role"
        )

        TrSecurityGroup = ec2.SecurityGroup(self, f"{project_name}-server-sg",
            security_group_name= f"{project_name}-server-sg", 
            vpc=vpc,
            allow_all_outbound=True,
        )
        Tags.of(TrSecurityGroup).add("Name", f"{project_name}-server-sg")
        TrSecurityGroup.add_ingress_rule(
            ec2.Peer.any_ipv4(),
            ec2.Port.tcp(22),
        )

        ToolTransferServer = transfer.CfnServer(
            self, "ToolTransferServer",
            endpoint_details=transfer.CfnServer.EndpointDetailsProperty(
                address_allocation_ids=[EIPTran01.attr_allocation_id,EIPTran02.attr_allocation_id],
                security_group_ids=[TrSecurityGroup.security_group_id], 
                subnet_ids=[Fn.import_value("PublicSubnet1a"),Fn.import_value("PublicSubnet1b")],
                vpc_id=vpc.vpc_id
            ),
            endpoint_type="VPC",
            identity_provider_details=transfer.CfnServer.IdentityProviderDetailsProperty(
                function=GetUserConfigLambda.function_arn,
                sftp_authentication_methods="PASSWORD",
            ),
            identity_provider_type="AWS_LAMBDA",
            logging_role=self.TransferServerRole.role_arn, 
            structured_log_destinations=[SFTPServerLogGroup.log_group_arn],
            tags=[
                CfnTag(
                    key="Name",
                    value="ToolTransferServer"
                ),
                CfnTag(
                    key="transfer:customHostname",
                    value="sftp.dev.ego.energy"
                )
            ]
        )

        GetUserConfigLambda.add_permission(
            "AllowTransferServer",
            principal=iam.ServicePrincipal("transfer.amazonaws.com"),
            action="lambda:InvokeFunction",
            source_arn=ToolTransferServer.attr_arn
        )


        #################
        #   SNS TOPIC   # 
        #################

        # snsTopic = sns.Topic( 
        #     self, 
        #     "ego-sftp-sns-topic",
        #     topic_name="ego-sftp-sns-topic",
        #     enforce_ssl=True,
        #     master_key=kms.Key.from_key_arn(
        #         self, 
        #         "SnsEncryptionKey", 
        #         sns_encryption_key
        #     )
        # )

        # snsTopic.add_to_resource_policy(
        #     iam.PolicyStatement(
        #         actions=["sns:Publish"],
        #         principals=[iam.ServicePrincipal("s3.amazonaws.com")],
        #         resources=[snsTopic.topic_arn],
        #     )
        # )

        #################
        #   S3 BUCKET   # 
        #################

        # self.bucket = s3.Bucket(
        #     self, "sftp-bucket-ego",
        #     bucket_name=f"ego-sftp-{Aws.ACCOUNT_ID}-{Aws.REGION}-aaa",  
        #     removal_policy=RemovalPolicy.RETAIN, 
        #     auto_delete_objects=False,  
        #     block_public_access=s3.BlockPublicAccess.BLOCK_ALL, 
        #     enforce_ssl=True,
        #     minimum_tls_version=1.2,
        #     encryption=s3.BucketEncryption.KMS,  
        #     encryption_key=kms.Key.from_key_arn(
        #         self, 
        #         "SFTPS3BucketEncryptionKey", 
        #         bucket_key
        #     ),
        #     server_access_logs_bucket=s3.Bucket.from_bucket_name(self, "logBucket", f"ego-resource-logs-{Aws.ACCOUNT_ID}-eu-west-1"), 
        #     server_access_logs_prefix="S3_ServerAccess_SFTP",
        #     versioned=False,  
        # )
        # self.bucket.add_event_notification(
        #     event=s3.EventType.OBJECT_CREATED_PUT,
        #     dest=s3n.SnsDestination(snsTopic)
        # )


        CfnOutput(self, "ServerID", export_name="ServerID", value=ToolTransferServer.attr_server_id)
        CfnOutput(self, "ServerEndpoint", export_name="ServerEndpoint", value=f"{ToolTransferServer.attr_server_id}.server.transfer.{Aws.REGION}.amazonaws.com")

        





    