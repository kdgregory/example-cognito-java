#!/bin/bash
#
# Creates a new user pool and client with minimal policies and attributes
# (ie, use for authentication only, no authorization or profile tracking).
#
#   cognite-create-userpool.sh POOL_NAME CLIENT_NAME
#

cat > /tmp/$$-pooldef.json <<EOF
{
    "Policies": {
        "PasswordPolicy": {
            "MinimumLength": 8,
            "RequireUppercase": true,
            "RequireLowercase": true,
            "RequireNumbers": true,
            "RequireSymbols": false
        }
    },
    "AutoVerifiedAttributes": [],
    "AliasAttributes": [],
    "MfaConfiguration": "OFF",
    "AdminCreateUserConfig": {
        "AllowAdminCreateUserOnly": true,
        "UnusedAccountValidityDays": 7
    },
    "Schema": [
        {
            "Name": "email",
            "StringAttributeConstraints": {
                "MinLength": "0",
                "MaxLength": "2048"
            },
            "DeveloperOnlyAttribute": false,
            "Required": true,
            "AttributeDataType": "String",
            "Mutable": true
        },
        {
            "AttributeDataType": "Boolean",
            "DeveloperOnlyAttribute": false,
            "Required": false,
            "Name": "email_verified",
            "Mutable": true
        }
    ]
}
EOF

cat > /tmp/$$-clientdef.json <<EOF
{
    "GenerateSecret": false, 
    "RefreshTokenValidity": 0, 
    "ReadAttributes": [], 
    "WriteAttributes": [],
    "ExplicitAuthFlows": [ "ADMIN_NO_SRP_AUTH" ]
}
EOF

aws cognito-idp create-user-pool --pool-name $1 --cli-input-json file:///tmp/$$-pooldef.json > /tmp/$$-pooldef-output.json

USER_POOL_ID=`jq ".UserPool.Id" < /tmp/$$-pooldef-output.json | sed -e 's/"//g'`
echo "User Pool ID: " $USER_POOL_ID

aws cognito-idp create-user-pool-client --user-pool-id $USER_POOL_ID --client-name $2 --cli-input-json file:///tmp/$$-clientdef.json > /tmp/$$-clientdef-output.json

echo "Client ID:    " `jq ".UserPoolClient.ClientId" < /tmp/$$-clientdef-output.json | sed -e 's/"//g'`
