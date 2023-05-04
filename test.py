import boto3

dynamodb = boto3.resource('dynamodb')

table = dynamodb.create_table(
    TableName='masteraiFriendships',
    KeySchema=[
        {
            'AttributeName': 'user1',
            'KeyType': 'HASH'
        },
        {
            'AttributeName': 'user2',
            'KeyType': 'RANGE'
        }
    ],
    AttributeDefinitions=[
        {
            'AttributeName': 'user1',
            'AttributeType': 'S'
        },
        {
            'AttributeName': 'user2',
            'AttributeType': 'S'
        },
    ],
    BillingMode='PAY_PER_REQUEST'
)

table.meta.client.get_waiter('table_exists').wait(TableName='masteraiFriendships')

print("Table status:", table.table_status)