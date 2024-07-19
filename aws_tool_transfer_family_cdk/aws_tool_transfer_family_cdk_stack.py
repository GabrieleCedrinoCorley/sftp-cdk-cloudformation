from aws_cdk import (
    Stack,
    aws_ec2 as ec2, 
    StackProps,     
)
from constructs import Construct

from ego_cdk import (
    Stage,
)
from constructs import Construct
from aws_tool_transfer_family_cdk.sftp import SFTP
from aws_tool_transfer_family_cdk.users import Users    

class AwsToolTransferFamilyCdkStack(Stack):

    def __init__(self, scope: Construct, construct_id: str,props: StackProps, repository_name: str, stage: Stage, image_tag: str, push_image: bool, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        self.project_name = "tool-transfer-family"

        vpc = ec2.Vpc.from_lookup(self, 'imported-ego-vpc', vpc_name="ego-vpc" )
        
        sftp = SFTP(self, 'sftp', vpc=vpc, stage=stage, project_name=self.project_name)

        #TODO rimettere questa chiamata e aggiungere il parametro bucket in users.py, quando creeremo il bucket da zero 
        #users = Users(self, 'users', bucket=sftp.bucket, TransferServerRole=sftp.TransferServerRole, stage=stage)

        users = Users(self, 'users', TransferServerRole=sftp.TransferServerRole, stage=stage)

        