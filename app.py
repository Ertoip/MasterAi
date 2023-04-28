from fastapi import FastAPI, Request, Depends, HTTPException, status, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import  CryptContext
from pydantic import BaseModel
from mangum import Mangum
import uvicorn
import openai
from hidden import keys
import boto3
from boto3.dynamodb.conditions import Key, Attr
import os
from typing import Annotated, Optional
import re
import uuid
from cachetools import TTLCache

#fastapi init
app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

#fastapi cors
origins = [
    "http://localhost",
    "http://localhost:8080",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

#dynamodb init
dynamodb = boto3.resource("dynamodb")

rulesTable = dynamodb.Table("masteraiRulesets")

friendsTable = dynamodb.Table("masteraiFriendships")

table = dynamodb.Table("MasterAiUsers")

#aws s3
session = boto3.session.Session(region_name='eu-west-3')
s3 = session.client('s3', config= boto3.session.Config(signature_version='s3v4'))
links = []
cache = TTLCache(maxsize=100, ttl=3600)  # Cache for 1 hour

# init openai
openai.api_key = keys.openai

# assistant config

#init auth
SECRET_KEY=keys.secret_key
ALGORITHM="HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 240

class User(BaseModel):
    id: str
    disabled: bool

# endpoint for ai messages
class message(BaseModel):
    msg: str
    
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user(username: str):
    res = table.query(
        IndexName='username-index',
        KeyConditionExpression=Key('username').eq(username)
    )
    
    try:
        return res["Items"][0]
    except:
        return False
    
def authenticate_user(username: str, password: str):
    user = get_user(username)
    if not user:
        return False
    if not verify_password(password, user["pswd"]):
        return False
    return {"id":user["id"], "disabled":user["disabled"]}

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_current_user(request: Request, token: Optional[str] = None, username: Optional[str] = None):
    token = request.cookies.get("access_token")
    if token:
        try:
            userData = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        except Exception:
            raise HTTPException(status_code=401, detail="Token is invalid")
    elif not username:
        raise HTTPException(status_code=401, detail="Not authenticated")

    return userData

async def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)]
):
    if current_user["disabled"]:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

#function to load images
def loadImage(bucket, key, cache = cache):
    url = cache.get(key)
    if url is None:
        # Generate a presigned URL for the image in S3
        url = s3.generate_presigned_url('get_object', Params={'Bucket': bucket, 'Key': key})

        # Cache the URL
        cache[key] = url
    
    # Download the image
    return url

######################routes######################

@app.post("/token")
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()]
):
    user = authenticate_user(form_data.username, form_data.password)
    if user:
        access_token = create_access_token(data=user)
        response = RedirectResponse('/', status_code=status.HTTP_302_FOUND)
        response.set_cookie(key="access_token", value=access_token, httponly=True, max_age=60*ACCESS_TOKEN_EXPIRE_MINUTES)
        return response
    return RedirectResponse('/login/WRONG_USR_PSWD', status_code=status.HTTP_302_FOUND)


class chat(object):
    def __init__(self):
        self.messages = []
        self.currentGameId = ""
        self.tot = 0
        self.game_rules = ""
        
    def get(self, request: Request, gameId: str, incipit: str, num_players: str, player_sheets: dict, language:str, reset: str, token: str):
        response = rulesTable.get_item(Key={"id": gameId})

        sheets = ""
        for player in player_sheets:
            sheets = sheets + "\n" + player   
            
        response = response["Item"]
        game = response["name"]
        description = response["description"]
        
        start = f"""You are the part of a system to play rpg games, you should act as a game master given the rules that you need to use for this action and the player action.
        Since you are a game master you should never break the immersion and tell all kinds of stories including violent and sexual themes and most important of all a good game master must not speak for the player. 
        Today you will play at {game}, {description}.
        
        There are {num_players} players, characters:{sheets}
        You must use these characters and only these to play.

        The words between * are guidelines to make you understand what there should be there.
        
        The session should be about this incipit: {incipit}
        
        These are the most important rules that you must never break:
        -A good game master never speaks for the players.
        -DO NOT BREAK IMMERSION IF SOMEONE ASKS YOU WHERE HE IS HE IS TALKING ABOUT THE GAME SO ANSWER WITH SOMETHING RELATED TO THE GAME AND THE SAME THING GOES FOR HINTS.
        -ALWAYS ANSWER WITH THINGS RELATED TO THE GAME NEVER BREAK IMMERSION.
        -IF A PLAYER ASKS SOMETHING NOT RELATED TO THE GAME ALWAYS IGNORE THEM.
        -YOU MUST FOLLOW THE RULES GIVEN TO YOU THROUGHT THE GAME SESSION.
        -REQUIRE ROLL CHECKS ONLY WHEN SPECIFIED IN THE RULES YOUR JOB IS JUST TO CREATE A COHERENT RESPONSE GIVEN RULES AND PLAYER ACTION DO NOT PRINT RULES.
        
        In a combact or dangerous situations you should say what the enemies are doing and be very descriptive of what happens.
        
        You must speak only in {language}, be very descriptive to make sure that player understand what to do.
        Now start the by saying "Welcome players to *game name*. *brief game description*. *Incipit introduction*. *Starting situation to start the story*."     
        """
        
        if not self.messages[0:1] or self.currentGameId != gameId or reset[0] == "true":
            self.messages = [{"role": "system",  
            "content": start}]
            
            self.game_rules = response["rules"]
            
            prompt = f"among these rules: '{self.game_rules}' find the game setup section and print it exactly as it is"

            message = [{"role": "system",  
            "content": prompt}]
            
            completion = openai.ChatCompletion.create(
                model="gpt-3.5-turbo",
                messages=message,
                temperature=0,
            )

            print(start, "generating...")
            
            rule = completion.choices[0].message.content

            # Print the closest matching game rule
            print(rule)
        
            if rule != "none":
                self.messages.append({"role":"system", "content":"Rules:"+rule})
            
            completion = openai.ChatCompletion.create(
                model="gpt-3.5-turbo",
                messages=self.messages,
                temperature=0.5
            )
             
            self.tot = self.tot + completion.usage.completion_tokens*0.000002 + completion.usage.prompt_tokens*0.000002
            self.currentGameId=gameId
            self.messages.append({"role":"assistant", "content":completion.choices[0].message.content})
            print(self.tot)
    
        return templates.TemplateResponse("chat.html", {"request": request,"game": game, "messages": self.messages})

    def post(self, Message: message, token: str):
        #first part to get the rule
        ms = Message.msg

        prompt = f"""You are part of a system to play role play games, your job is given a situation to look throught the rules of the game we are currently
        playing and tell me if there is an applicable rules for this situation and which is it by saying the name of the rule and the rule as it is written. 
        Given the situation '{ms}', print out the rules needed in this situation '{self.game_rules}'.
        If there is no applicable rule say just 'none' and nothing else"""

        message = [{"role": "system",  
        "content": prompt}]
        
        print("received")
        
        completion = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=message,
            temperature=0
        )
        
        self.tot = completion.usage.completion_tokens*0.000002 + completion.usage.prompt_tokens*0.000002        
        rule = completion.choices[0].message.content
        print(rule)
        #second part return the result    
        self.messages.append({"role":"user", "content":ms})
        
        if rule != "none":
            self.messages.append({"role":"system", "content":"Rules:"+rule})
        
        completion = openai.ChatCompletion.create(
            model="gpt-3.5-turbo", 
            messages=self.messages,
            temperature=1,
        )
        
        self.tot = completion.usage.completion_tokens*0.000002 + completion.usage.prompt_tokens*0.000002
        print(self.tot)
                
        ms = completion.choices[0].message.content
        self.messages.append({"role":"assistant", "content": ms})
        return ms

ct = chat()

@app.post('/game', response_class=HTMLResponse)
async def get(request: Request, token: str = Depends(get_current_active_user)):
    form_data = await request.form()
    gameId = form_data.get("gameId")
    incipit = form_data.get("incipit")
    num_players = form_data.get("num_players")
    player_sheets = form_data.getlist("player_sheets[]")
    reset = form_data.getlist("reset")
    language = form_data.getlist("language")
    
    return ct.get(request, gameId, incipit, num_players, player_sheets, language, reset, token)
    
@app.post("/messages")
async def post_message(Message: message, token: str = Depends(get_current_active_user)):
    return ct.post(Message, token)

#login page
@app.get("/login")
async def login(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.get("/login/{msg_code}")
async def login(request: Request, msg_code: str):
    message = ""
    if msg_code == "REG_SUC":
        message = "Registration successful now login to verify account"
    if msg_code == "NOT_AUTH":
        message = "Authentication error"
    if msg_code == "WRONG_USR_PSWD":
        message = "Invalid username or password"
        
    return templates.TemplateResponse("login.html", {"request": request, "message": message})

#registration page
@app.get("/registration")
async def registrationPage(request: Request):
    return templates.TemplateResponse("registration.html", {"request": request})

#user registration
@app.post("/registration")
async def register(
    request: Request, 
    username: Annotated[str, Form()], 
    email: Annotated[str, Form()], 
    password: Annotated[str, Form()]
):
    
    usernameQuery = table.query(
        IndexName='username-index',
        KeyConditionExpression=Key('username').eq(username)
    )
    usernameQuery=usernameQuery["Items"]
    emailQuery = table.query(
        IndexName='email-index',
        KeyConditionExpression=Key('email').eq(email)
    )
    emailQuery=emailQuery["Items"]
        
    if len(password)< 8:
        message = "Password must be longer than 8 characters"
    elif re.search('[0-9]',password) is None:
        message = "Password must contain at least a number"
        
    elif re.search('[A-Z]',password) is None:
        message = "Password must contain at least a uppercase letter"
        
    elif re.search('[a-z]',password) is None:
        message = "Password must contain at least a lowercase letter"
    
    elif usernameQuery or emailQuery:
        message = "email or username already in use"
    
    else:
        while True:
            new_user_id = str(uuid.uuid4())

            response = table.get_item(Key={"id": new_user_id})

            if 'items' not in response:
                pswdHash = get_password_hash(password)

                new_user = {'id': new_user_id,
                            'username': username,
                            'email': email,
                            'pswd': pswdHash,
                            'disabled':False, 
                            'language':'english', 
                            'icon':'pfp/default.jpg',
                            'created':str(datetime.now()), 
                            'last_modified':str(datetime.now())}
                
                table.put_item(Item=new_user)
                message = "REG_SUC"
                response = RedirectResponse('/login/REG_SUC', status_code=status.HTTP_302_FOUND)
                
                return response
                
    return templates.TemplateResponse("registration.html", {"request": request, "message": message})

#post and get request for adding game to db
@app.get("/addGame/{response_id}")
@app.get("/addGame")
async def addGameGet(request: Request, response_id: str = None ,token: str = Depends(get_current_active_user)):  
    message = "" 
    bucket_name = 'masteraibucket'
    s3_objects = s3.list_objects(Bucket=bucket_name, Prefix="icons")
        
    # Generate list of image URLs
    images = []
    for s3_object in s3_objects['Contents']:
        object_key = s3_object['Key']
        if object_key.endswith('.jpg') or object_key.endswith('.jpeg') or object_key.endswith('.png'):
            images.append({
                "link":loadImage(bucket_name, object_key),
                "key": s3_object["Key"]
            })
    
    print(response_id)
    
    if response_id == "SUC":
        message = "Game added successfully"

    return templates.TemplateResponse("addGame.html", {"request": request, "message": message, "image_urls":images})

@app.post("/addGame")
async def addGamePost(request: Request, name: Annotated[str, Form()] = "No name",description: Annotated[str, Form()] = "No description", rules: Annotated[str, Form()] = "No rules", icon: Annotated[str, Form()] = "icon/image (50).jpg", token: str = Depends(get_current_active_user) ):   
    while True:
        new_game_id = str(uuid.uuid4())

        response = rulesTable.get_item(Key={"id": new_game_id})
        if 'items' not in response:
            new_game = {'id': new_game_id,
                        'name': name, 
                        "description":description, 
                        'rules': rules, 
                        "userId":token["id"], 
                        "icon": icon,                             
                        'created':str(datetime.now()), 
                        'last_modified':str(datetime.now())}
            
            rulesTable.put_item(Item=new_game)
            message = "SUC"
            
            return RedirectResponse('/addGame/'+message, status_code=status.HTTP_302_FOUND)

@app.get("/editRules")
async def editGame(request: Request, token: str = Depends(get_current_active_user)):  
    res = rulesTable.query(
        IndexName='userId-index',
        KeyConditionExpression=Key('userId').eq(token["id"])
    )  
    
    games = []
    bucket_name = 'masteraibucket'
    
    if "Items" in res:
        games = res["Items"]
        
        for game in games:
            key = game['icon']
            game['icon'] = loadImage(bucket_name, key)
    
    return templates.TemplateResponse("editRules.html", {"request": request, "games":games})

#edit single game
@app.get("/edit/{gameId}/{response_id}")
@app.get("/edit/{gameId}")
def edit(request: Request, gameId: str, response_id:str = None, token: str = Depends(get_current_active_user)):
    response = rulesTable.get_item(Key={"id": gameId})
    
    if "Item" in response:
        response = response["Item"]
        r = str(response["rules"])  
        game = response["name"]   
        key = response['icon']
        description = response["description"]
        message = ""
        
        bucket_name = 'masteraibucket'
        s3_objects = s3.list_objects(Bucket=bucket_name, Prefix="icons")
        images = []

        #remove already existing keys
        s3_objects['Contents'] = [d for d in s3_objects['Contents'] if d.get('Key') != key]
        
        for s3_object in s3_objects['Contents']:
            object_key = s3_object['Key']
            if object_key.endswith('.jpg') or object_key.endswith('.jpeg') or object_key.endswith('.png'):
                images.append({
                    "link":loadImage(bucket_name, object_key),
                    "key": s3_object["Key"]
                })
        
        icon = {"link":loadImage(bucket_name, key),
                "key":key}
        
        if response_id == "SUC":
            message = "game updated"
        
        return templates.TemplateResponse("edit.html", {"request": request,
                                                        "id": gameId, 
                                                        "name": game, 
                                                        "rules":r, 
                                                        "images": images,
                                                        "icon": icon,
                                                        "description": description,
                                                        "message":message})
            
    return RedirectResponse('/editRules', status_code=status.HTTP_302_FOUND)


@app.post("/edit/{gameId}")
def submitEdit(request: Request, gameId: str,  name: Annotated[str, Form()] = "No name",description: Annotated[str, Form()] = "No description", rules: Annotated[str, Form()] = "No rules", icon: Annotated[str, Form()] = "icon/image (50).jpg", token: str = Depends(get_current_active_user)):
    rulesTable.update_item(
        Key={
            'id': gameId  # assuming 'id' is the primary key of your table
        },
        UpdateExpression='SET #n = :val1, #r = :val2, #i = :val3, #d = :val4, #t = :val5',
        ExpressionAttributeNames={
            '#n': 'name',
            '#r': 'rules',
            '#i': 'icon',
            '#d': 'description',
            '#t': 'last_modified'
        },
        ExpressionAttributeValues={
            ':val1': name,
            ':val2': rules,
            ':val3': icon,
            ':val4': description,
            ':val5': str(datetime.now())
        }
    )

    message = "SUC"
    return RedirectResponse('/edit/'+gameId+"/"+message, status_code=status.HTTP_302_FOUND)

@app.post("/delete/{gameId}")
def deleteGame(request: Request, gameId: str, token: str = Depends(get_current_active_user)):
    response = rulesTable.get_item(Key={"id": gameId})
    
    if "Item" in response:
        response = response["Item"]
        if response["userId"] == token["id"]:
            
            rulesTable.delete_item(
                Key={
                    'id': gameId
                }
            ) 
    
    return RedirectResponse('/editRules', status_code=status.HTTP_302_FOUND)



#homepage
@app.get("/")
async def loadHome(request: Request, token: str = Depends(get_current_active_user)): 
    response = table.get_item(Key={"id": token["id"]})
    response = response["Item"]
    bucket_name = 'masteraibucket'
    icon = loadImage(bucket_name, response["icon"])
    return templates.TemplateResponse("home.html", {"icon":icon, "request": request})

#shop
@app.get("/shop")
async def shop(request: Request, token: str = Depends(get_current_active_user)):  
    return templates.TemplateResponse("shop.html", {"request": request})

#settings
@app.get("/settings")
async def settings(request: Request, token: str = Depends(get_current_active_user)): 
    
    response = table.get_item(Key={"id": token["id"]})
    
    if "Item" in response:
        response = response["Item"]
        key = response["icon"]
        
        bucket_name = 'masteraibucket'
        s3_objects = s3.list_objects(Bucket=bucket_name, Prefix="pfp")
        images = []
        
        s3_objects['Contents'] = [d for d in s3_objects['Contents'] if d.get('Key') != key]

        for s3_object in s3_objects['Contents']:
            object_key = s3_object['Key']
            if object_key.endswith('.jpg') or object_key.endswith('.jpeg') or object_key.endswith('.png'):
                images.append({
                    "link":loadImage(bucket_name, object_key),
                    "key": s3_object["Key"]
                })
        
        icon = {"link":loadImage(bucket_name, key), "key":key}

        return templates.TemplateResponse("settings.html", {"user":response, "images": images,"icon": icon, "request": request})
    
    return RedirectResponse('/', status_code=status.HTTP_302_FOUND)


#settings
@app.post("/settings")
async def settingsPost(request: Request, icon: Annotated[str, Form()], language: Annotated[str, Form()],token: str = Depends(get_current_active_user)): 
    
    table.update_item(
        Key={
            'id': token["id"]  # assuming 'id' is the primary key of your table
        },
        UpdateExpression='SET #l = :val1, #i = :val2, #t = :val3',
        ExpressionAttributeNames={
            '#l': 'language',
            '#i': 'icon',
            '#t': 'last_modified'
        },
        ExpressionAttributeValues={
            ':val1': language,
            ':val2': icon,
            ':val3': str(datetime.now())
        }
    )

    return RedirectResponse('/settings', status_code=status.HTTP_302_FOUND)

#select game to play
@app.get("/gameSelection")
async def selectGame(request: Request, token: str = Depends(get_current_active_user)):
    games = rulesTable.query(
        IndexName='userId-index',
        KeyConditionExpression=Key('userId').eq(token["id"])
    )
    
    bucket_name = 'masteraibucket'
    
    if "Items" in games:
        games = games["Items"]    
        
        for game in games:
            key = game['icon']
            game['icon'] = loadImage(bucket_name, key)
        
    return templates.TemplateResponse("gameSelection.html", {"request": request, "games":games})

#friend page
@app.get("/friends")
async def friends(request: Request, token: str = Depends(get_current_active_user)): 
        
    #get all friendships on user 1
    response = friendsTable.query(
        KeyConditionExpression = Key('user1').eq(token["id"])
    )
    
    ids = []
    bucket_name = 'masteraibucket'


    if "Items" in response:
        response = response["Items"]
        print(response)
        
        for friend in response:
            ids.append({"id":friend["user2"]})
        
    #get items on user 2
    response = friendsTable.query(
        IndexName='user2-user1-index',
        KeyConditionExpression = Key('user2').eq(token["id"])
    )
    
    if "Items" in response:
        response = response["Items"]
        print(response)
        
        for friend in response:
            ids.append({"id":friend["user1"]})
    
    response = dynamodb.batch_get_item(
        RequestItems={
            'MasterAiUsers': {
                'Keys': ids
            }
        }
    )
    
    print(response)
    
    friends = response["Responses"]['MasterAiUsers']
    
    for friend in friends:
        friend["icon"] = loadImage(bucket_name, friend["icon"])
    
    return templates.TemplateResponse("friends.html", {"friends":friends, "request": request})

#add friendship
@app.post("/addFriend")
async def addFriend(request: Request, friendName: Annotated[str, Form()], token: str = Depends(get_current_active_user)): 

    usernameQuery = table.query(
        IndexName='username-index',
        KeyConditionExpression=Key('username').eq(friendName)
    )
       
    print(usernameQuery)    
    user2 = usernameQuery["Items"]
    if user2[0:1]:
        user1 = table.get_item(Key={"id": token["id"]})
        user1 = user1["Item"]
        user2 = user2[0]
        print(user1)
        print(user2)
        
        if user1["username"] != user2["username"]:
            friendsTable.put_item(
                Item={
                    'user1': token['id'],
                    'user2': user2['id'],
                    'friendship_status': True,
                    'created':str(datetime.now()), 
                    'last_modified':str(datetime.now())
                }
            )
            
            return RedirectResponse('/friends', status_code=status.HTTP_302_FOUND)

    return RedirectResponse('/friends', status_code=status.HTTP_302_FOUND)

#select game to play
@app.get("/gamePage/{gameId}")
async def gamePage(request: Request, gameId: str, token: str = Depends(get_current_active_user)):
    response = rulesTable.get_item(Key={"id": gameId})

    response = response["Item"]
    bucket_name = 'masteraibucket'
    response["icon"] = loadImage(bucket_name, response["icon"])
    
    user = table.get_item(Key={"id": token["id"]})
    user = user["Item"]
    
    return templates.TemplateResponse("gamepage.html", {"request": request, "user":user, "game":response})


#logiut remove token
@app.get("/logout")
def logout(request: Request, token: str = Depends(get_current_active_user)):
    response = RedirectResponse('/login', status_code=status.HTTP_302_FOUND)
    response.delete_cookie(key="access_token")
    return response

#handle exceptions like not authenticated users
@app.exception_handler(HTTPException)
async def custom_exception_handler(request, exc):
    return RedirectResponse('/login/NOT_AUTH', status_code=status.HTTP_302_FOUND)

handler = Mangum(app)

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1")
