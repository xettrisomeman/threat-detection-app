import hashlib
import shap
import matplotlib.pyplot as plt

SECURE_KEY = "Si.[|/1M(yY-TK6sRNyswje-+ATQ;~}kgj)_30f75SSEEF*Ketpd>=,^G?8Z"

def hash_password(password: str):
    key = SECURE_KEY.encode("utf-8")
    password = password.encode("utf-8")
    return hashlib.sha256(key+password).hexdigest()

def verify_password(password, hashed_password):
    hashes = hash_password(password)
    return hashes == hashed_password


def force_plot_html(explainer, shap_values, ind):
    force_plot = shap.plots.force(shap_values[ind], 
                     matplotlib=False)
    shap_html = f"<head>{shap.getjs()}</head><body>{force_plot.html()}</body>"
    return shap_html


def save_beeswarm_plot(shap_values, figurename):
    shap.plots.beeswarm(shap_values, show=False)
    plt.savefig(figurename, bbox_inches='tight')
    

def save_waterfall_plot(shap_values, ind, figurename):
    shap.plots.waterfall(shap_values[ind], show=False)
    plt.savefig(figurename, bbox_inches='tight')
    
    