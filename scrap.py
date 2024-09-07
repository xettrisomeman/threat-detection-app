import httpx
import urllib.parse
import pandas as pd

from bs4 import BeautifulSoup
try:
    from functools import cache
except:
    from functools import lru_cache as cache

from collections import Counter


# import onnxruntime as rt

 
 
@cache
def get_soup(url):
    req = httpx.get(url)
    soup = BeautifulSoup(req, "lxml")
    return soup


def numdots(url):
    return len(url.split("."))-1

# count the level of path in url
def pathlevel(url):
    paths = urllib.parse.urlparse(url).path.split("/")    
    return len([path for path in paths if path])

# count the number of "-"" in url
def numdash(url):
    return len(url.split("-"))-1

# check if https exist
def nohttps(url):
    return int("https" in urllib.parse.urlparse(url).scheme.lower())

# check pathlength
def pathlength(url):
    return len(urllib.parse.urlparse(url).path)

# cehck query length
def querylength(url):
    return len(urllib.parse.urlparse(url).query)

# check the count of sensitive words
def numsensitivewords(url):
    sensitive_words = ["secure", "account", "webscr", "login", "ebayisapi", "signin", "banking", "confirm"]
    count = 0
    for word in sensitive_words:
        if word in url:
            count+=1
    return count

@cache
def pctexthyperlinks(url):
    """Count the percentage of external hyperlinks in webpage html source code
    
    Arguments:
    Url: Url of a wesbite Type:String
    
    return: continuous data"""
    
    soup = get_soup(url)
    alink = soup.find_all("a")
    all_hyperlinks = [tag['href'] for tag in alink if "href" in tag.attrs]
    external_hyperlinks = [resource_url for resource_url in all_hyperlinks 
                           if urllib.parse.urlparse(resource_url).netloc != urllib.parse.urlparse(url).netloc 
                               and urllib.parse.urlparse(resource_url).netloc != ""]
    
    
    total_hyperlinks = len(all_hyperlinks)
    
    total_external_hyperlinks = len(external_hyperlinks)
    
    if total_hyperlinks > 0:
        return round((total_external_hyperlinks / total_hyperlinks) * 100, 1)
    else:
        return 0


def pctextresourceurls(url):
    """Counts the percentage of external resource URLs in webpage HTML source
code""" 

    soup = get_soup(url)
    resource_tags = soup.find_all(['img', 'link', 'input', "frame", "iframe"], src=True)
    
    
    
    all_resource_urls = [tag['src'] for tag in resource_tags if 'src' in tag.attrs]
    
    domain_name = urllib.parse.urlparse(url).netloc.split(".")[0]
    url = urllib.parse.urlparse(url).netloc
    

  
    # all_resource_urls = [url for url in _all_resource_urls if url[-3:] not in ["png", "svg", "jpg", "gif"]]
    
    external_resource_urls = [resource_url for resource_url in all_resource_urls 
                              if urllib.parse.urlparse(resource_url).netloc != url and urllib.parse.urlparse(resource_url).netloc != "" and domain_name not in url]
    
    total_resource_urls = len(all_resource_urls)
    total_external_resource_urls = len(external_resource_urls)    
    if total_resource_urls > 0:
        return round((total_external_resource_urls / total_resource_urls) * 100, 1)
    return 0


def extfavicon(url):
    soup = get_soup(url)
    head_icon = soup.find("head")
    if head_icon:
        favicon_links = head_icon.find_all("link")
        icon = None
        domain_name = urllib.parse.urlparse(url).netloc.split(".")[0]
    
        url = urllib.parse.urlparse(url).netloc
        for link in favicon_links:
           if link['rel'][0] in ['icon', 'favicon']:
                icon = link['href']
        check_icon = False if url == urllib.parse.urlparse(icon).netloc or urllib.parse.urlparse(icon).netloc == "" or domain_name not in url else True
        return int(check_icon)
    return 0


def insecureforms(url):
    soup = get_soup(url)
    form = soup.find("form")
    domain_name = urllib.parse.urlparse(url).netloc.split(".")[0]
    
    url = urllib.parse.urlparse(url).netloc
    if form:
        if "action" in form.attrs:
            form_action = form['action']
            check_form = False if url == urllib.parse.urlparse(form_action).netloc or urllib.parse.urlparse(form_action).netloc == "" or domain_name not in url else True
            return int(check_form)
    return 0



def pctnullselfredirecthyperlinks(url):
    soup = get_soup(url)
    alink = soup.find_all("a")
    
    all_hyperlinks = [tag['href'] for tag in alink if "href" in tag.attrs] 
    
    total_hyperlinks = len(all_hyperlinks)
    redirect_count = 0
    domain_name = urllib.parse.urlparse(url).netloc.split(".")[0]
    
    url_netloc = urllib.parse.urlparse(url).netloc
    for hyperlink in all_hyperlinks:
        netloc = urllib.parse.urlparse(hyperlink).netloc
        if netloc == "" or netloc == url_netloc or domain_name in url_netloc:
            redirect_count += 1
            
    if redirect_count > 0:
        return round((redirect_count / total_hyperlinks) * 100, 1)
    return 0



def frequentdomainnamemismatch(url):
    soup = get_soup(url)
    
    alink = soup.find_all("a")
    
    links = [url for url in alink if 'href' in url.attrs]
    
    all_hyperlinks = [tag['href'] for tag in links if tag['href'].startswith("http") or tag['href'].endswith(".com")]
    
    domain_name = urllib.parse.urlparse(url).netloc.split(".")[0]
    if all_hyperlinks:
        frequent_domain_name = Counter(all_hyperlinks).most_common(1)[0][0]
        original_domain_netloc = urllib.parse.urlparse(url).netloc
        frequent_domain_netloc = urllib.parse.urlparse(frequent_domain_name).netloc
        return int(original_domain_netloc != frequent_domain_netloc and domain_name not in original_domain_netloc)
    else:
        return 0

    

def submitinfotoemail(url):
    soup = get_soup(url)
    form = soup.find("form")
    alinks = soup.find_all("a")
    
    if form:
        if "action" in form.attrs:
            if "mailto" in form['action']:
                return 1
    for link in alinks:
        if "href" in link.attrs:
            if "mailto" in link['href']:
                return 1
    return 0
    
            

def extmetascriptlinkrt(url):
    """Counts percentages of meta, scrip and link tags containing external url in the attributes. Apply rules and thresholds to generate values
    -1=> Legimate(0-17%)
    0=> suspicious (0-17 and <81)
    1=> phishing (>81)
    """
    
    soup = get_soup(url)
    resource = soup.find_all(["link", "meta", "script"])
    
    domain_name = urllib.parse.urlparse(url).netloc.split(".")[0]
    url_netloc = urllib.parse.urlparse(url).netloc
    all_urls = []
    for resc in resource:
        if "src" in resc.attrs:
            all_urls.append(resc['src'])
        elif "href" in resc.attrs:
            all_urls.append(resc['href'])
        else:
            continue
    
    total_urls = len(all_urls)
    external_urls = [rurl for rurl in all_urls if urllib.parse.urlparse(rurl).netloc != url_netloc and urllib.parse.urlparse(rurl).netloc != "" and domain_name not in url_netloc]   
    
    external_urls_count = len(external_urls)
    
    percentage = 0
    if total_urls > 0:
        percentage = round((external_urls_count/total_urls) * 100, 1)
    else:
        percentage = 0
        
        
    #rule -> https://eprints.hud.ac.uk/id/eprint/24330/6/MohammadPhishing14July2015.pdf
    if percentage < 17:
        return -1
    elif percentage >= 17 and percentage <= 81:
        return 0
    else:
        return 1 

    

def pctextnullselfredirecthyperlinksrt(url):
    """_summary_

    Args:
        url (_type_): _description_
    """
    
    soup = get_soup(url)
    
    urls = soup.find_all("a")
    
    domain_name = urllib.parse.urlparse(url).netloc.split(".")[0]
    url_netloc = urllib.parse.urlparse(url).netloc
    
    resource_urls = [url['href'] for url in urls if "href" in url.attrs]
    external_urls = len([rurl for rurl in resource_urls if urllib.parse.urlparse(rurl).netloc != url_netloc and urllib.parse.urlparse(rurl).netloc != "" and domain_name not in url_netloc])
    
    anchor_list_len = len([eurl for eurl in resource_urls if eurl.startswith("#") or eurl.lower().startswith("java")])
    
    
    total_urls = len(urls)
    percentage = 0
    if total_urls > 0:
        percentage = round((anchor_list_len / total_urls) * 100 + (external_urls / total_urls) * 100, 1)
    else:
        percentage = 0
        
        
    if percentage < 31:
        return -1
    elif percentage >= 31 and percentage <= 67:
        return 0
    else:
        return 1


def convert_to_df(url):
    features = {}
    features['NumDots'] = numdots(url)
    features['PathLevel'] = pathlevel(url)
    features['NumDash'] = numdash(url)
    features['NoHttps'] = nohttps(url)
    features['PathLength'] = pathlength(url)
    features['QueryLength'] = querylength(url)
    features['NumSensitiveWords'] = numsensitivewords(url)
    features['PctExtHyperlinks'] = pctexthyperlinks(url)
    features['PctExtResourceUrls'] = pctextresourceurls(url)
    features['ExtFavicon'] = extfavicon(url)
    features['InsecureForms']= insecureforms(url)
    features['PctNullSelfRedirectHyperlinks'] = pctnullselfredirecthyperlinks(url)
    features['FrequentDomainNameMismatch'] = frequentdomainnamemismatch(url)
    features['SubmitInfoToEmail'] = submitinfotoemail(url)
    features['ExtMetaScriptLinkRT'] = extmetascriptlinkrt(url)
    features['PctExtNullSelfRedirectHyperlinksRT'] = pctextnullselfredirecthyperlinksrt(url)
    # print(featuress)
    df = pd.DataFrame([features])
    return df





# model = rt.InferenceSession("phishing-detection.onnx")



def check_http(url: str):
    if url.startswith("https://") or url.startswith("http://"):
        try:
            url = httpx.get(url)
            return url.status_code
        except httpx.ConnectError as e:
            return e 
    else:
        return "Not a valid url!"
