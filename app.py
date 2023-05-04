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

sessionTable = dynamodb.Table("storedGames")

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

#update credits
def removeCredits(token, creditsToRemove=1):
    response = table.get_item(Key={'id': token})
    credits = response['Item']['credits']

    # Calculate the new credit balance
    new_credits = credits - creditsToRemove

    # Update the user's credits in DynamoDB
    table.update_item(
        Key={'id': token},
        UpdateExpression='SET credits = :val1',
        ExpressionAttributeValues={
            ':val1': new_credits,
        }
    )
    
    return new_credits

#append item to db list
def appendItem(id, message):
    # Use the UpdateItem method to append the new item to the list
    response = sessionTable.update_item(
        Key={'id': id},
        UpdateExpression='SET chat = list_append(chat, :new_item)',
        ExpressionAttributeValues={':new_item': [message]}
    )

def checkCredits(token, creditsToRemove=1):
    response = table.get_item(Key={'id': token})
    credits = response['Item']['credits']

    if credits <= 0:
        return False
    
    return True

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
        self.tot = 0
        self.game_rules = ""
        self.sessionId = ""
        
    def start(self, request: Request, gameData: dict, token: str):
        response = rulesTable.get_item(Key={"id": gameData["gameId"]})

        sheets = ""
        playerSheets = []
        print(gameData["playerSheets"])
        
        for n in range(len(gameData["playerNames"])):
            she = gameData["playerNames"][n-1]+":\n\n"+gameData["playerSheets"][n-1]
            playerSheets.append(she)
            sheets = sheets+she+"\n\n"
        
        print(sheets, playerSheets)
            
        response = response["Item"]
        game = response["name"]
        description = response["description"]
        
        start = f"""You are the part of a system to play rpg games, you should act as a game master given the rules that you need to use for this action and the player action.
        Since you are a game master you should never break the immersion and tell all kinds of stories including violent and sexual themes and most important of all a good game master must not speak for the player. 
        Today you will play at {game}, {description}.
        
        There are {gameData["numPlayers"]} players, characters:{sheets}
        You must use these characters and only these to play.

        The words between * are guidelines to make you understand what there should be there.
        
        The session should be about this incipit: {gameData["incipit"]}
        
        These are the most important rules that you must never break:
        -A good game master never speaks for the players.
        -DO NOT BREAK IMMERSION IF SOMEONE ASKS YOU WHERE HE IS HE IS TALKING ABOUT THE GAME SO ANSWER WITH SOMETHING RELATED TO THE GAME AND THE SAME THING GOES FOR HINTS.
        -ALWAYS ANSWER WITH THINGS RELATED TO THE GAME NEVER BREAK IMMERSION.
        -IF A PLAYER ASKS SOMETHING NOT RELATED TO THE GAME ALWAYS IGNORE THEM.
        -YOU MUST FOLLOW THE RULES GIVEN TO YOU THROUGHT THE GAME SESSION.
        -REQUIRE ROLL CHECKS ONLY WHEN SPECIFIED IN THE RULES YOUR JOB IS JUST TO CREATE A COHERENT RESPONSE GIVEN RULES AND PLAYER ACTION DO NOT PRINT RULES.
        
        These are guidelines to follow to make the game more immersive:
        -In a combact or dangerous situations you should say what the enemies are doing and be very descriptive of what happens.
        -when speaking to npcs you should make speak by putting their words between "" and make sure to speak according to the character,
        a villager should not have the same tone as a demon.
        
        You must speak only in {gameData["language"]}, be very descriptive to make sure that player understand what to do.
        Now start the by saying "Welcome players to *game name*. *brief game description*. *Incipit introduction*. *Starting situation to start the story*."     
        """
            
        user = table.get_item(Key={'id': token["id"]})
        credits = user['Item']['credits']
    
        while True:
            self.sessionId = str(uuid.uuid4())

            storedItem = sessionTable.get_item(Key={"id": self.sessionId})

            if 'items' not in storedItem:
                new_item = {'id': self.sessionId,
                            'name': gameData["name"],
                            'icon':'pfp/default.jpg',
                            'description':gameData["incipit"],
                            'owner':token["id"],
                            'gameRuleset':gameData["gameId"],
                            'chat': [],
                            'icon': gameData["icon"],
                            'numPlayers': gameData["numPlayers"],
                            'playerSheets':playerSheets,
                            'language':gameData["language"],
                            'created':str(datetime.now()), 
                            'last_modified':str(datetime.now())}
                
                sessionTable.put_item(Item=new_item)
                
                break

        
        if credits > 0:
            message = [{"role": "system",  
            "content": start}]
            self.messages = message
            
            appendItem(self.sessionId, message[0])
            
            self.game_rules = response["rules"]
            
            prompt = f"among these rules: '{self.game_rules}' find the game setup section and print it exactly as it is"

            message = [{"role": "system",  
            "content": prompt}]
            
            appendItem(self.sessionId, message[0])
            
            completion = openai.ChatCompletion.create(
                model="gpt-3.5-turbo",
                messages=message,
                temperature=0,
            )

            print("generating...")
            
            rule = completion.choices[0].message.content

            # Print the closest matching game rule        
            if rule != "none":
                self.messages.append({"role":"system", "content":"Rules:"+rule})
            
            completion = openai.ChatCompletion.create(
                model="gpt-3.5-turbo",
                messages=self.messages,
                temperature=0.5
            )
            
            credits = credits - 1

            # Update the user's credits in DynamoDB
            table.update_item(
                Key={'id': token["id"]},
                UpdateExpression='SET credits = :val1',
                ExpressionAttributeValues={
                    ':val1': credits,
                }
            )
                        
            self.tot = self.tot + completion.usage.completion_tokens*0.000002 + completion.usage.prompt_tokens*0.000002
            message={"role":"assistant", "content":completion.choices[0].message.content}
            self.messages.append(message)
            appendItem(self.sessionId, message) 
            print(self.tot, completion.usage.completion_tokens + completion.usage.prompt_tokens)
    
            return templates.TemplateResponse("chat.html", {"request": request,"game": game, "id":gameData["gameId"], "credits":credits, "messages": self.messages, "url":"gamePage"})
        
        #ad ad ad ad ad ad ad ad ad ad ad ad ad ad ad ad ad ad ad
        return templates.TemplateResponse("chat.html", {"request": request,"game": game, "id":gameId, "credits":"This should start and ad", "messages": self.messages, "url":"gamePage"})

    def resume(self, request: Request, gameData: dict, token: str):
        response = sessionTable.get_item(Key={"id": gameData["gameId"]})

        if "Item" in response and response["Item"]["owner"] == token["id"]:
            response = response["Item"]
            user = table.get_item(Key={"id": token["id"]})

            if "Item" in user:
                user = user["Item"]
                self.messages = response["chat"]
                print(self.messages)
                print(self.messages[0])

                self.sessionId = gameData["gameId"]
            
                return templates.TemplateResponse("chat.html", {"request": request,"game": response["name"], "id":gameData["gameId"], "credits":user["credits"], "messages": self.messages, "url":"loadPage"})
        
        return RedirectResponse('/addGame/'+message, status_code=status.HTTP_302_FOUND)

    def message(self, Message: message, token: str):
        
        if checkCredits(token["id"]):
            # first part to get the rule
            ms = Message.msg

            prompt = f"""You are part of a system to play role play games, your job is given a situation to look through the rules of the game we are currently
            playing and tell me if there is an applicable rule for this situation and which is it by saying the name of the rule and the rule as it is written. 
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
            
            # second part return the result    
            ms = {"role":"user", "content":ms}
            self.messages.append(ms)
            appendItem(self.sessionId, ms)

            if rule != "none":
                self.messages.append({"role":"system", "content":"Rules:"+rule})
            
            # remove messages with "system" role between third and last two messages
            messages_to_remove = [msg for msg in self.messages[3:-2] if msg["role"] == "system"]
            for msg in messages_to_remove:
                self.messages.remove(msg)
            
            completion = openai.ChatCompletion.create(
                model="gpt-3.5-turbo", 
                messages=self.messages,
                temperature=1,
            )
            
            credits = removeCredits(token["id"])
            
            self.tot = completion.usage.completion_tokens*0.000002 + completion.usage.prompt_tokens*0.000002
            print(self.tot, completion.usage.completion_tokens + completion.usage.prompt_tokens)
                    
            ms = completion.choices[0].message.content
            self.messages.append({"role":"assistant", "content": ms})
            appendItem(self.sessionId, {"role":"assistant", "content": ms})

            return ms, credits
        
        #ad ad ad ad ad ad ad ad ad ad ad ad ad ad ad ad ad ad ad ad ad ad ad ad ad ad ad
        ms = ""
        return ms, "This should start an ad"


ct = chat()

@app.post('/game', response_class=HTMLResponse)
async def get(request: Request, token: str = Depends(get_current_active_user)):
    form_data = await request.form()
    gameData = {
        "gameId": form_data.get("gameId"),
        "incipit": form_data.get("incipit"),
        "numPlayers": form_data.get("num_players"),
        "playerNames": form_data.getlist("names"),
        "playerSheets": form_data.getlist("sheets"),
        "name": form_data.get("name"),
        "language": form_data.get("language"),
        "icon": form_data.get("icon")
    }
    
    return ct.start(request, gameData, token)

@app.post('/resume', response_class=HTMLResponse)
async def resume(request: Request, token: str = Depends(get_current_active_user)):
    form_data = await request.form()
    gameData = {
        "gameId": form_data.get("gameId"),
    }
    
    return ct.resume(request, gameData, token)

@app.post("/messages")
async def post_message(Message: message, token: str = Depends(get_current_active_user)):
    return ct.message(Message, token)

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
                            'info':'',
                            'credits': 25,
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
    user = table.get_item(Key={"id": token["id"]})
    user = user["Item"]
    return templates.TemplateResponse("shop.html", {"request": request, "credits":user["credits"]})

@app.post("/buy")
async def buy(request: Request, product: Annotated[int, Form()] = None, token: str = Depends(get_current_active_user)):  
    creditRanges = [70, 400, 900]
    if product:
        response = table.get_item(Key={'id': token["id"]})
        credits = response['Item']['credits']

        # Calculate the new credit balance
        new_credits = credits + creditRanges[product-1]

        # Update the user's credits in DynamoDB
        table.update_item(
            Key={'id': token["id"]},
            UpdateExpression='SET credits = :val1',
            ExpressionAttributeValues={
                ':val1': new_credits,
            }
        )
    
    return RedirectResponse('/shop', status_code=status.HTTP_302_FOUND)

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
async def settingsPost(request: Request, icon: Annotated[str, Form()] = " ", info: Annotated[str, Form()] = " ", language: Annotated[str, Form()] = " ",token: str = Depends(get_current_active_user)): 
    
    table.update_item(
        Key={
            'id': token["id"]  # assuming 'id' is the primary key of your table
        },
        UpdateExpression='SET #l = :val1, #i = :val2, #f = :val3, #t = :val4',
        ExpressionAttributeNames={
            '#l': 'language',
            '#i': 'icon',
            '#f': 'info',
            '#t': 'last_modified'
        },
        ExpressionAttributeValues={
            ':val1': language,
            ':val2': icon,
            ':val3': info,
            ':val4': str(datetime.now()),
            
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
            
    # Query for shared1 where user1 is the token user
    response1 = friendsTable.query(
        KeyConditionExpression=Key('user1').eq(token["id"])
    )
    shared2 = []
    for res in response1["Items"]:        
        shared2.extend(res['shared2'])

    # Query for shared2 where user2 is the token user
    response2 = friendsTable.query(
        IndexName='user2-user1-index',
        KeyConditionExpression=Key('user2').eq(token["id"])
    )
    shared1 = []
    for res in response2["Items"]:
        shared1.extend(res['shared1'])


    # Merge the shared1 and shared2 arrays
    shared = shared1 + shared2
    retrieved_items = []
    
    if len(shared) > 0:
        # Use the shared items to create a list of batch get requests
        ids = []
        for item_id in shared:
            ids.append({"id":item_id})
        
        response = dynamodb.batch_get_item(
            RequestItems={
                'masteraiRulesets': {
                    'Keys': ids
                }
            }
        )

        # Extract the retrieved items from the response
        retrieved_items = response['Responses']['masteraiRulesets']
        
        for game in retrieved_items:
            game['icon'] = loadImage(bucket_name, game["icon"])

        
        
    return templates.TemplateResponse("gameSelection.html", {"request": request, "games":games, "shared":retrieved_items})

#load game to resume
@app.get("/loadGames")
async def loadGames(request: Request, token: str = Depends(get_current_active_user)):
    games = sessionTable.query(
        IndexName='owner-index',
        KeyConditionExpression=Key('owner').eq(token["id"])
    )
    
    bucket_name = 'masteraibucket'
    
    if "Items" in games:
        games = games["Items"]    
        
        for game in games:
            key = game['icon']
            game['icon'] = loadImage(bucket_name, key)

    return templates.TemplateResponse("loadGames.html", {"request": request, "games":games})

#resume page game
@app.get("/loadPage/{gameId}")
async def loadPage(request: Request, gameId: str, token: str = Depends(get_current_active_user)):
    response = sessionTable.get_item(Key={"id": gameId})

    response = response["Item"]
    bucket_name = 'masteraibucket'
    response["icon"] = loadImage(bucket_name, response["icon"])
    response["numPlayers"] = int(response["numPlayers"])
        
    rules = rulesTable.get_item(Key={"id": response["gameRuleset"]})
    rules = rules["Item"]
    
    return templates.TemplateResponse("loadpage.html", {"request": request, "rules":rules, "game":response})

@app.post("/deleteSession/{gameId}")
def deleteSession(request: Request, gameId: str, token: str = Depends(get_current_active_user)):
    response = sessionTable.get_item(Key={"id": gameId})

    if "Item" in response:
        response = response["Item"]
        if response["owner"] == token["id"]:
            
            sessionTable.delete_item(
                Key={
                    'id': gameId
                }
            ) 
    
    return RedirectResponse('/loadGames', status_code=status.HTTP_302_FOUND)

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
            
    print(ids)
    if ids[0:1]:
        response = dynamodb.batch_get_item(
            RequestItems={
                'MasterAiUsers': {
                    'Keys': ids
                }
            }
        )
            
        friends = response["Responses"]['MasterAiUsers']
        
        for friend in friends:
            friend["icon"] = loadImage(bucket_name, friend["icon"])
    else:
        friends = []
           
    return templates.TemplateResponse("friends.html", {"friends":friends, "request": request})

#add friendship
@app.post("/addFriend")
async def addFriend(request: Request, friendName: Annotated[str, Form()], token: str = Depends(get_current_active_user)): 
    usernameQuery = table.query(
        IndexName='username-index',
        KeyConditionExpression=Key('username').eq(friendName)
    )
    
    if usernameQuery["Items"][0:1]:
        user2 = usernameQuery["Items"][0]

        response = dynamodb.batch_get_item(
            RequestItems={
                'masteraiFriendships': {
                    'Keys': [
                        {'user1': token["id"], 'user2': user2["id"]},
                        {'user1':  user2["id"], 'user2': token["id"]}
                    ]
                }
            }
        )
        
        if 'Responses' not in response:
            user1 = table.get_item(Key={"id": token["id"]})
            user1 = user1["Item"]
                        
            if user1["username"] != user2["username"]:
                friendsTable.put_item(
                    Item={
                        'user1': token['id'],
                        'user2': user2['id'],
                        'friendship_status': True,
                        'shared1': [],
                        'shared2': [],
                        'created':str(datetime.now()), 
                        'last_modified':str(datetime.now())
                    }
                )
                
                return RedirectResponse('/friends', status_code=status.HTTP_302_FOUND)

    return RedirectResponse('/friends', status_code=status.HTTP_302_FOUND)

#select friend to play
@app.get("/friend/{friendId}")
async def friend(request: Request, friendId: str, token: str = Depends(get_current_active_user)):
    response = dynamodb.batch_get_item(
        RequestItems={
            'masteraiFriendships': {
                'Keys': [
                    {'user1': token["id"], 'user2': friendId},
                    {'user1': friendId, 'user2': token["id"]}
                ]
            }
        }
    )
    
    if 'Responses' in response:
        items = response['Responses']['masteraiFriendships']

        if items:
            response = table.get_item(Key={"id": friendId})

            response = response["Item"]
            bucket_name = 'masteraibucket'
            response["icon"] = loadImage(bucket_name, response["icon"])
            
            games = rulesTable.query(
                IndexName='userId-index',
                KeyConditionExpression=Key('userId').eq(token["id"])
            )
            
            if games["Items"][0:1]:
                games = games["Items"]    
                for game in games:
                    game["icon"] = loadImage(bucket_name, game["icon"])
            else:
                games = []
                
            if items[0]["user1"] == friendId:
                share = items[0]["shared2"]
            else:
                share = items[0]["shared1"]
                
            return templates.TemplateResponse("friend.html", {"username":response["username"],
                                                            "info":response["info"],
                                                            "icon":response["icon"],
                                                            "id": friendId,
                                                            "games":games,
                                                            "share": share,
                                                            "request": request})

@app.post("/deleteFriend/{friendId}")
def deleteFriend(request: Request, friendId: str, token: str = Depends(get_current_active_user)):

    friendsTable.delete_item(
        Key={
            'user1': friendId,
            'user2': token["id"],
        }
    )
    
    friendsTable.delete_item(
        Key={
            'user1': token["id"],
            'user2': friendId,
        }
    )
    
    return RedirectResponse('/friends', status_code=status.HTTP_302_FOUND)

@app.post("/share/{friendId}")
async def shareGame(request: Request, friendId: str, token: str = Depends(get_current_active_user)):
    form_data = await request.form()
    games = form_data.getlist("games")
    secure = []
    
    for game in games:
        response = rulesTable.query(
            KeyConditionExpression=Key('id').eq(game)
        )
        if 'Items' in response:
            item = response['Items'][0]
            if item['userId'] != token["id"]:
                continue # Skip adding this game to the list
        
        secure.append(game)
        
    try:
        friendsTable.update_item(
            Key={'user1': token["id"], 'user2': friendId},
            UpdateExpression='SET #s = :val1, #t = :val2',
            ExpressionAttributeNames={
                '#s': 'shared1',
                '#t': 'last_modified'
            },
            ExpressionAttributeValues={
                ':val1': secure,
                ':val2': str(datetime.now()),
                
            }
        )
    except:  
        friendsTable.update_item(
            Key={
                'user2': token["id"],
                'user1': friendId
            },
            UpdateExpression='SET #s = :val1, #t = :val2',
            ExpressionAttributeNames={
                '#s': 'shared2',
                '#t': 'last_modified'
            },
            ExpressionAttributeValues={
                ':val1': secure,
                ':val2': str(datetime.now()),
                
            }
        )
        
    return RedirectResponse('/friend/'+friendId, status_code=status.HTTP_302_FOUND)

#select game to play
@app.get("/gamePage/{gameId}")
async def gamePage(request: Request, gameId: str, token: str = Depends(get_current_active_user)):
    response = rulesTable.get_item(Key={"id": gameId})

    response = response["Item"]
    bucket_name = 'masteraibucket'
    response["icon"] = loadImage(bucket_name, response["icon"])
    
    user = table.get_item(Key={"id": token["id"]})
    user = user["Item"]
    
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
    
    return templates.TemplateResponse("gamepage.html", {"request": request, "user":user, "game":response, "images": images})

#select game to play
@app.get("/sharedPage/{gameId}")
async def gamesharedPagePage(request: Request, gameId: str, token: str = Depends(get_current_active_user)):
    game = rulesTable.get_item(Key={"id": gameId})

    game = game["Item"]
    bucket_name = 'masteraibucket'
    game["icon"] = loadImage(bucket_name, game["icon"])
    
    user = table.get_item(Key={"id": token["id"]})
    user = user["Item"]
    
    og = table.get_item(Key={"id": game["userId"]})
    og = og["Item"]["username"]
    
    return templates.TemplateResponse("gamepage.html", {"request": request, "user":user, "game":game, "og": og})

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
