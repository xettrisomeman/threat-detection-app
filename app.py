import uvicorn
try:
    from typing import Annotated
except:
    from typing_extensions import Annotated
from contextlib import asynccontextmanager
from starlette.middleware.sessions import SessionMiddleware

from utils import hash_password, verify_password, force_plot_html, \
    save_waterfall_plot
from scrap import convert_to_df, check_http
from database import get_db, create_database
from models import User, UserRequests
from lime.lime_text import LimeTextExplainer
from catboost import CatBoostClassifier
# import onnxruntime as rt
from sklearn.model_selection import train_test_split
import shap
import pandas as pd


from fastapi.staticfiles import StaticFiles 
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session
from fastapi import FastAPI, Request, Depends, Form, Response, status
from fastapi.responses import HTMLResponse,  RedirectResponse
from fastapi.templating import Jinja2Templates



from joblib import load
import matplotlib

matplotlib.pyplot.switch_backend('Agg')


@asynccontextmanager
async def lifespan(app: FastAPI):
    create_database()
    yield


app = FastAPI(lifespan=lifespan)
app.add_middleware(SessionMiddleware, secret_key="some-random-string")

templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")



@app.exception_handler(404)
def custom_404_handler(request: Request, __):
    return templates.TemplateResponse(
    name = "404.html", context={"request": request}
    )


@app.get("/", response_class=HTMLResponse)
def homepage(request: Request, db: Session = Depends(get_db)):
    if request.session.get("sub") is None:
        return RedirectResponse("/login")
    
    user = db.query(User).filter_by(username=request.session.get("sub")).first()
    if user:
        user_requests = user.requests
        return templates.TemplateResponse(
                name="homepage.html", context={"request": request, "user_requests": user_requests}
            )
    else:
        return RedirectResponse("/register")
        
@app.get("/login", response_class=HTMLResponse)
def login_formview(request: Request):
    error = request.query_params.get("error")
    if error:
        mapping = {
        "user_does_not_exist": "User Does Not Exist!",
        "incorrect_password": "Incorrect Password!!"
        }
        value = mapping[error]
    else:
        value = None
    if request.session.get("sub") is None:
        return templates.TemplateResponse(
        name="login.html", context={"request": request, "error": value}
    )
    return templates.TemplateResponse(
        name="homepage.html", context={"request": request}
    )
    
@app.post("/login", response_class=HTMLResponse)
def login(request: Request, username: Annotated[str, Form(...)],
                   password: Annotated[str, Form(...)],
                   db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username==username).first()
    if user:
        if verify_password(password, user.hashed_password):
            request.session['sub'] = username
            return RedirectResponse(
                url="/", status_code=status.HTTP_303_SEE_OTHER
            )
        else:
            return RedirectResponse(
                url="/login?error=incorrect_password", status_code=status.HTTP_303_SEE_OTHER
            )
    return RedirectResponse(
                url="/login?error=user_does_not_exist", status_code=status.HTTP_303_SEE_OTHER
            )


@app.get("/register", response_class=HTMLResponse)
def register_formview(request: Request):
    error = request.query_params.get("error")
    if error:
        mapping = {
        "username_exists": "User Already Exists!",
        "password_does_not_match": "Password does not match!!"
        }
        value = mapping[error]
    else:
        value = None
    if request.session.get("sub") is None:
        return templates.TemplateResponse(
            name="register.html", context={"request": request, "error":value}
        )
    return templates.TemplateResponse(
        name="homepage.html", context={"request": request}
    )

@app.post("/register", response_class=HTMLResponse)
def register_form(username: Annotated[str, Form(...)],
                   password: Annotated[str, Form(...)],
                   verify_password: Annotated[str, Form(...)],
                   db: Session = Depends(get_db)):
    
    check_username = db.query(User).filter_by(username=username).first()
    if check_username:
        return RedirectResponse(
            url="/register?error=username_exists", status_code=status.HTTP_303_SEE_OTHER
            )
    elif password != verify_password:
        return RedirectResponse(
            url="/register?error=password_does_not_match", status_code=status.HTTP_303_SEE_OTHER
            )
        
    hashed_password = hash_password(password)
    user = User(username=username, hashed_password=hashed_password)    
    db.add(user)
    db.commit()
    
    return RedirectResponse(
        url="/login", status_code=status.HTTP_303_SEE_OTHER
    )

@app.post("/logout")
def logout(request: Request):
    request.session['sub'] = None
    return templates.TemplateResponse(
        name="login.html", context={"request": request}
    )

@app.post("/sqli")
def sqli(request: Request, query: Annotated[str, Form(...)],
         db: Session = Depends(get_db)):
    vectorizer = load("models/sqli/tfidfvec")
    pipe = load("models/sqli/sqli_pipe")
    prediction = pipe.predict([query])[0]
    classes=["Normal", "SQLInjection"]
    mapper = {
    1 :"SQLInjection",
    0: 'Normal'
    }
    mapping_function = lambda x: mapper[x]
    pred = mapping_function(prediction)
    
    ## user request creation
    user = db.query(User).filter_by(username=request.session["sub"]).first()
    user_request = UserRequests(text=query, request=pred)
    user.requests.append(user_request)
    db.add(user_request)
    db.commit()

    
    explainer = LimeTextExplainer(class_names=classes)
    exp = explainer.explain_instance(query, pipe.predict_proba, num_features=len(vectorizer.get_feature_names_out()))    
    exp = exp.as_html()
    text = "LIME-explained results using LogisticRegression"
    return templates.TemplateResponse(
        name="homepage.html", context = {"request": request, 
                                         "exp": exp, 
                                         "prediction": pred,
                                         "text": text,
                                         "attack": "SqliInjection",
                                         "user_requests": user.requests}
    )



@app.post("/xss")
def xss(request: Request, query: Annotated[str, Form(...)],
        db: Session = Depends(get_db)):
    vectorizer = load("models/xss/tfidfvec")
    pipe = load("models/xss/pipe")
    prediction = pipe.predict([query])[0]
    classes=["Normal", "Xss Attack"]
    mapper = {
    1 :"Xss Attack",
    0: 'Normal'
    }
    mapping_function = lambda x: mapper[x]
    pred = mapping_function(prediction)
    
    user = db.query(User).filter_by(username=request.session["sub"]).first()
    user_request = UserRequests(text=query, request=pred)
    user.requests.append(user_request)
    db.add(user_request)
    db.commit()
    
    explainer = LimeTextExplainer(class_names=classes)
    exp = explainer.explain_instance(query, pipe.predict_proba, num_features=len(vectorizer.get_feature_names_out()))    
    exp = exp.as_html()
    text = "LIME-explained results using LogisticRegression"
    return templates.TemplateResponse(
        name="homepage.html", context = {"request": request, 
                                         "exp": exp, 
                                         "prediction": pred,
                                         "text": text,
                                         "attack": "Xss Attack",
                                         "user_requests": user.requests}
    )
    
@app.post("/phishing_detect")
def phishing_detect(request: Request, query: Annotated[str, Form(...)],
                    db: Session = Depends(get_db)):
    req = check_http(query)
    if isinstance(req, int):
        model = CatBoostClassifier().load_model("models/phishing/phishing-detection")
        df = pd.read_csv("models/phishing/Phishing.csv")
        X = df.loc[:, ~df.columns.isin(["CLASS_LABEL", "id"])]
        y = df.loc[:, df.columns =="CLASS_LABEL"]
        X_train, _ , _, _ = train_test_split(X, y, stratify=y, random_state=42)
        data = convert_to_df(query)
        # features = list(data.columns)
        # X2 = X.loc[:, X.columns.isin(features)]
        mapper = ["Not a Phishing site!", "Phishing site!"]
        prediction = model.predict(data)[0]
        
    
    
        #classes = ['safe', 'unsafe']
        #explainer = lime.lime_tabular.LimeTabularExplainer(X2.to_numpy(), class_names=classes, feature_names = features,
        #kernel_width=5, verbose=False, mode="classification")
        #exp = explainer.explain_instance(data.to_numpy()[0], model.predict_proba, num_features=15)
        
        explainer = shap.Explainer(model)
        pred = mapper[prediction]

        ####################
        user = db.query(User).filter_by(username=request.session["sub"]).first()
        user_request = UserRequests(text=query, request=pred)
        user.requests.append(user_request)
        db.add(user_request)
        db.commit()
        ###################
        
                
        shap_values = explainer(data)        
        exp = force_plot_html(explainer, shap_values, 0)
        waterfall_plot = "static/waterfall.png"
        save_waterfall_plot(shap_values, ind=0, figurename=waterfall_plot)
        text = "SHAP-explained results using CatBoostClassifier"
    
        return templates.TemplateResponse(
        name="homepage.html", context = {"request": request, 
                                         "exp": exp, 
                                         "prediction": pred,
                                         "text": text,
                                         "attack": "Phishing Attack",
                                         "plot": waterfall_plot,
                                         "user_requests": user.requests[::-1]}
        )
    else:
        return templates.TemplateResponse(
            name="homepage.html", context={"request": request, "error": req}
        )
        

    
if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
