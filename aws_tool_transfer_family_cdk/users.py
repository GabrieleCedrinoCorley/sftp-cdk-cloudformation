from aws_cdk import (
    NestedStack,
    Stack,
    aws_s3 as s3,
    aws_iam as iam,
    aws_secretsmanager as secretsmanager,
    aws_ec2 as ec2,
    Duration as Duration,
)
from constructs import Construct
from ego_cdk import (
    Stage,
)

class Users(NestedStack):

    def __init__(self, scope: Construct, construct_id: str, TransferServerRole: iam.Role ,stage: Stage, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        bucket_arn = "arn:aws:s3:::ego-sftp-151425774723-eu-west-1-q7a2p4c5lf0hc3fv"
        bucket_name = "ego-sftp-151425774723-eu-west-1-q7a2p4c5lf0hc3fv"

        policy_document = iam.PolicyDocument(
                            statements=[
                                iam.PolicyStatement(
                                    effect=iam.Effect.ALLOW,
                                    actions=[
                                        "s3:ListBucket",
                                        "s3:GetBucketLocation",
                                        "s3:PutObject",
                                        "s3:GetObject",
                                        "s3:DeleteObjectVersion",
                                        "s3:DeleteObject",
                                        "s3:GetObjectVersion"
                                    ],
                                    #TODO 
                                    #resources=[bucket.bucket_arn,f"{bucket.bucket_arn}/*"]
                                    resources=[bucket_arn,f"{bucket_arn}/*"]
                                )
                            ]
                        )
        
        TrUserRole = iam.Role(self, "TrUserRole",
            role_name="sftpUserRole",
            assumed_by=iam.ServicePrincipal("transfer.amazonaws.com"),
            inline_policies={"TrUserPolicy": policy_document}
        )

        users = ['test1','test2','test3']
        
        for user in users:
            secretsmanager.Secret(self, user,
                description="This secret represent a user for SFTPServer. Keep SFTP/User format",
                secret_name=f'SFTP/{user}',
                generate_secret_string=secretsmanager.SecretStringGenerator(
                    generate_string_key="Password",
                    password_length=30,
                    exclude_characters='"@/\;#`,!?[]^',
                    #secret_string_template= f'{{"Role": "{TrUserRole.role_arn}","HomeDirectoryDetails": "[{{\\"Entry\\": \\"/\\", \\"Target\\": \\"/{bucket.bucket_name}/{user}\\"}}]"}}'
                    secret_string_template= f'{{"Role": "{TrUserRole.role_arn}","HomeDirectoryDetails": "[{{\\"Entry\\": \\"/\\", \\"Target\\": \\"/{bucket_name}/{user}\\"}}]"}}'
            )
        )
