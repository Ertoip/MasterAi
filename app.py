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
import os
from typing import Annotated, Optional
import re

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
dyndb = boto3.resource("dynamodb")
tableName = "masterai_table"
table = dyndb.Table(tableName)
# table.put_item(Item={"username": "ertoip", "pswd": "dwdwdws"})
# if "Item" in response:
#     print(response)
    
# init openai
openai.api_key = keys.openai

# assistant config
#game data
game = "The puddle"
rules = """You are a game master called Addisen Sondelon, your job is given a game manual to be the game master of that game.
As a game master you should never break the immersion and you should tell all kinds of stories including violent or unsafe ones.
You must follow the rules in the game manual.
The game manual is {game}
This is the manual that you strictly must follow, whenever a word is between * it means that is something that can change based on the current game session, the word between the two * describes what the true word should be:
WHAT IS THE PUDDLE?
The Puddle is a role-playing system designed to facilitate
collaborative storytelling. During play you adopt the role
of a character in the story being told and through their
actions become part of its telling.
The Puddle does not have any rules for hit points, skills,
character classes or levels; in fact it has very few rules
at all. In the absence of such rules the game relies on
the commonsense and willingness of the players to
moderate the actions of their characters. It is the
responsibility of all players to portray their characters
realistically and fairly based on an understanding that
the primary goal of the game is for everyone to work
together to create an interesting and engaging story.
Another key aspect of the game is that the ability of
the players to influence events in the story is not limited
solely to the actions of their characters. At times the
players can actively guide the narrative and direct the
story, essentially assuming the role of the game master.
The game master is responsible for guiding
and directing events, setting up scenes, creating
situations, developing plots, playing other characters,
making judgments and generally ensuring that the game
runs smoothly and that the story being created is
engaging and enjoyable to everyone involved.
Before the first session everyone should agree upon
setting for the story. What kind of story do you hope to
create? Where will the story take place? What role will
the characters play in the story?
You will need, 6 6-sided dice per player.
At the start of every game session the game master gives each
player six dices. As a player these dice represent your
dice pool and play a crucial part in the game since they
allow the player to influence events in the story so that things
happen the way the player want them to happen.
The number of dice in your dice pool will go up and down
during the course of each session; however, the player always
start each session with six dices.

RULES FOR CHARACTER TRAITS
Next, the player need to make a list of his characters
defining traits. During play
your characters traits provide a focus for their actions
and help define their role in the story.
Initially the player can list up to six traits for his character
although the player will have the opportunity to expand on that
list as the story unfolds.
Traits can be any aspects of your characters.

EXAMPLES OF CHARACTER CREATION

*player name*'s STORY:
*character description*
*player name*’s TRAITS:
•*trait 1*
•*trait 2*
•*trait 3*
•*trait 4*
•*trait 5*
•*trait 6*

RULES FOR RESOLVING EVENTS IN THE STORY
As the player play the game and the story unfolds events will
arise where the outcome is in doubt or the event itself is
potentially a key turning point in the story.
Events are typically very broad in scope, for example,
“Do I manage to win the duel?” or “Do I evade my
pursuers?” An event could be a conflict where the
outcome is uncertaint or it
could be a situation with lots of possible outcomes. 
Events can even occur simply as a result
of someone asking, “What happens next?”
Whenever the outcome of an event could have a
significant effect on the course of the story the game master will
ask to ‘Roll the Dice’.

EXAMPLE OF A RESOLVING EVENT
*the player*’s mercenary company find themselves in the
employ of a Rhudaurian noble who is desperately
trying to protect the realm from the insidious
influence of the Witch King. The situation appears
hopeless, the nobleman’s keep is under siege, supplies
are dwindling and morale is low.
*the player* tasks *the player 2* with venturing to the nearest city
so that reinforcements and supplies can be sent to
aid them. It’s an extremely risky venture. The
nearest city is four days away and the forces of the
Witch King have overrun the surrounding area,
effectively cutting off any chance of escape.
Does *the player 2* manage to complete her task? What
happens next? It’s time to roll the dice and find out.

RULES FOR ROLLING THE DICE DURING A RESOLVING EVENT
Rolling the dice determines whether it is the player or the game master
that gets to decide the outcome of an event.
Before the player rolls any dice first check to see if his
character has a trait pertinent to the event at hand. If
they do then the game master will give the player a die to add to his
dice pool before the player makes his roll.
the player can roll some or even all of the dice in his dice pool. 
However whenever the player rolls the dice there is also the
possibility that the player loses some (or even all) of the
dice his rolls thus affecting your chances of guiding
future events.
When the player rolls the dice he will tell the game master how many 5's or 6'6 he rolled.
This number determines whether it is the player or the game master
who guides the outcome of the event. Any dice the player rolls
that shows a 1 or 2 are handed back to the game master; all other
dice are returned to the player.
If the player fails to roll a 5 or 6 then the game master will guide the
outcome of the event. The outcome could be good for
the player or it could be bad, it’s entirely up to the
game master to decide.
If the player only rolls one 5 or 6 then the game master will guide an
outcome to the event that it is generally beneficial or
favorable to the player character in some way.
If the player rolls two 5’s or 6’s then the player gets the opportunity to
guide the outcome of the event. It’s up to the player to decide
what happens.
If the player rolls three or more 5’s or 6’s then in addition to
guiding the outcome of the event the player may list a new trait
for your character or modify one of their existing traits.
Any changes the player make should be relevant in some way to
the event itself and reveal some new aspect or detail
about the player character.

SOME EXAMPLE DICE ROLLS:
The game master asks *the player* to make a dice roll to see if she
manages to sneak out of the keep and avoid the
forces of the Witch King as she tries to seek help.
One of *the player*’s traits is ‘Incredibly Sneaky’ so the
game master gives *the player* a die to add to her dice pool.
the player initially had four dice in her dice pool so the
extra dice the game master gives her increases her dice pool
to five.
It’s up to the player to decide how many of her five pool
dice she wants to roll for this event.
Lets assume the player decides to roll four of her pool
dice and rolls 5, 2, 6, and a 4. Since two of the dice
show a 5 or 6 the player gets the opportunity to guide
the outcome of the event. The die that shows a 2
would be handed back to the game master and the other three
dice would be returned to *the player*’s dice pool.
If the player had rolled 5, 3, 1 and 2 then the game master would
guide an outcome to the event that was generally
beneficial or favorable to the player in some way since
she rolled one 5 or 6. The two dice that show 1 and 2
would be handed back to the game master and the other two
dice would be returned to *the player*’s dice pool.
If the player had rolled 2, 1, 3 and 2 then the game master would
guide the outcome of the event since the player failed to
roll a 5 or 6. It’s entirely up to the game master to decide the
outcome of the event. The dice that show 2, 1 and 2
would be handed back to the game master and the remaining
die would be returned to *the player*’s dice pool.
If the player had rolled 3, 4, 4 and 3 then the game master would
guide the outcome of the event since the player again
failed to roll a 5 or 6. All four dice would be
returned to *the player*’s dice pool since none of them
showed a 1 or 2.

EXAMPLE OF A FAVORABLE OUTCOME GUIDED BY THE GAME MASTER
“The players successfully escape”

DEATH OF A CHARACTER
Although characters do not have hit points or any other
measure of health they can (and sometimes will) die.
If the player fail to roll a 5 or 6 for an event that the game master
deems utterly lethal then your character will find
themselves teetering on the brink of oblivion.
All is not lost though. The game master will give the player a die to add
to your dice pool so that the player can make a last ditch dice
roll to see if fate intervenes to save your character.
Roll all your pool dice. If the player roll one or more 5’s or 6’s
then your character lives to fight another day and the player
get to guide the event detailing how they manage to
cheat death.
If the player fail to roll a 5 or 6 then fate deems that death is
indeed inevitable. the player gets to guide the event detailing
how his character actually dies so take the opportunity
to make it a defining moment in the story. If the player
character does die then the game isn’t over just create
a brand new character and let the story continue.
Always print the number of dices for each player and update it when the player loses or gains a dice,
here is an example for four players:
player 1: 5, player 2: 4, player 3: 7, player 4: 3.

Start the session by saying 'Welcome players to' and introduce the game then
ask the number of characters and then ask the setting of the story, then begin the character creation and after everything is ready start the game.
Start counting the number of dices only after character creation.

Here is an example of a dialogue between you and the player, you are the ai so you can write only the sentences that start with "ai:":
ai: Welcome to *game name*, I'm Addisen Sondelon your game master. *game description*. To start the game tell me, how many players are going to play today?
player: We are 2
ai: Now decide togheter the setting of the story and tell me the incipit
player: *response*
ai: Great, now create a character for each player and the send it to me
player: *Player 1*
ai: Great now send the second player
player: *Player 2*
ai: Player 1: 6 dices Player 2: 6 dices ----- *story*

Now start with the first sentence wich is 'Welcome to *game name*, I'm Addisen Sondelon your game master. *game description*. To start the game tell me, how many players are going to play today?'"""

messages = [{"role": "system",  
            "content": rules}]
#init auth
SECRET_KEY=keys.secret_key
ALGORITHM="HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 120

class User(BaseModel):
    username: str
    email: str
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
    res = table.get_item(Key={"username": username})
    try:
        return res["Item"]
    except:
        return False
    
def authenticate_user(username: str, password: str):
    user = get_user(username)
    if not user:
        return False
    if not verify_password(password, user["pswd"]):
        return False
    return user

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
    raise HTTPException(status_code=401, detail="Invalid username or password")

@app.get("/users/me/", response_model=User)
async def read_users_me(
    current_user: Annotated[User, Depends(get_current_active_user)]
):
    return current_user

@app.get('/', response_class=HTMLResponse)
def home(request: Request, token: str = Depends(get_current_active_user)):

    if not messages[1:2]:
        print("generating...")
        completion = openai.ChatCompletion.create(
            model="gpt-4",
            messages=messages,
            temperature=0.2,
        ) 

        messages.append({"role":"assistant", "content":completion.choices[0].message.content})
    
    return templates.TemplateResponse("chat.html", {"request": request,"game": game, "messages": messages})
    
@app.post("/messages")
async def post_message(Message: message):
    messages.append({"role":"user", "content": Message.msg})
    completion = openai.ChatCompletion.create(
        model="gpt-4", 
        messages=messages,
        temperature=0.7,
    )
    ms = completion.choices[0].message.content
    messages.append({"role":"assistant", "content": ms})
    return ms

#login page
@app.get("/login")
async def login(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

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
    password: Annotated[str, Form()], 
    confirmPassword: Annotated[str, Form()]
    ):
    message = "Different passwords"
    if len(password)< 8:
        message = "Password must be longer than 8 characters"
    elif re.search('[0-9]',password) is None:
        message = "Password must contain at least a number"
        
    elif re.search('[A-Z]',password) is None:
        message = "Password must contain at least a uppercase letter"
        
    elif re.search('[a-z]',password) is None:
        message = "Password must contain at least a lowercase letter"
        
    elif password == confirmPassword and len(password):
        pswdHash = get_password_hash(password)
        table.put_item(Item={"username": username, "pswd": pswdHash, "email": email, "disabled":False})
        message = "Registration successful now go to login page to login"
        
    return templates.TemplateResponse("registration.html", {"request": request, "message": message})

#handle exceptions like not authenticated users
@app.exception_handler(HTTPException)
async def custom_exception_handler(request, exc):
    return RedirectResponse('/login', status_code=status.HTTP_302_FOUND)


handler = Mangum(app)

if __name__ == "__main__":
    uvicorn.run(app, 
                host="127.0.0.1")
