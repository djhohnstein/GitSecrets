from termcolor import colored
from urllib.parse import urlencode
import requests
import json
from optparse import OptionParser
from bs4 import BeautifulSoup
import re
from regexes import queries

max_threads = 1
cur_threads = 0

def print_warning(content, color="yellow"):
    print(colored("[WARNING] {}".format(content), color))

def print_info(content, color="yellow"):
    print(colored("[INFO] {}".format(content), color))

def print_success(content, color="green"):
    print(colored("[SUCCESS] {}".format(content), color))

def print_error(content, color="red"):
    print(colored("[ERROR] {}".format(content), color))

def print_debug(content, color="blue"):
    print(colored("[DEBUG] {}".format(content), color))

def parse_repo_links(soup, base_url):
    """
    Return all hyperlinks to repositories on a github page.

    :param soup: BeautifulSoup object of a page on a user repository.
    :return: Links.
    """

    domain = base_url.split("/")[2]
    # for d in repo_list:
    ssh_url = "git@{}:{}"
    hrefs = [ssh_url.format(domain, x.get("href")[1:]) for x in soup.findAll("a", {"itemprop": "name codeRepository"})]
    return(hrefs)

def find_local_repos():
    """

    :return: List of file paths to git directories.
    """
    d = '.'
    dir_path = os.path.realpath(d)
    # print("Dir path: {}".format(dir_path))
    partial_git_dirs = [os.path.join(d, o)[1:] for o in os.listdir(d) if os.path.isdir(os.path.join(d, o)) and ".git" in os.listdir(os.path.join(d,o))]
    # print("Partial git dirs: {}".format(partial_git_dirs))
    git_dirs = [dir_path + x for x in partial_git_dirs]
    return git_dirs

def git_clone(href):
    global cur_threads
    if href[-4:] != ".git":
        href += ".git"
    try:
        with open("/dev/null","w") as devnull:
            subprocess.run(["git","clone",href], stdout=devnull, stderr=devnull)
            print("[+] Cloned {} sucessfully.".format(href))
    except subprocess.CalledProcessError:
        print("[-] Failed to clone repository at: {}".format(href))
    cur_threads -= 1

def trufflehog(repo, outdir):
    """
    Runs trufflehog on a list of git repositories.

    :param repos: List of filepaths to git directories.
    :return: None
    """
    if outdir[-1] != "/":
        outdir += "/"

    repo_name = repo.split("/")[-1]
    try:
        cmd = subprocess.run(["trufflehog", "file://{}".format(repo)], stdout=subprocess.PIPE)
        outfile = outdir + repo_name + ".trufflehog"
        with open(outfile, 'wb') as f:
            f.write(cmd.stdout)
        print("[+] Analyzed repo: {}".format(repo_name))
    except Exception as e:
        print("Error in running trufflehog. Reason: {}".format(e))
    global cur_threads
    cur_threads -= 1

def del_repos(repos):
    """
    Remove a list of directories.
    :param repos: List of directory strings.
    :return: None
    """
    for repo in repos:
        try:
            subprocess.run(["rm", "-rf", repo])
        except subprocess.CalledProcessError:
            print("[!] Could not delete repo: {}".format(repo))


def parse_cookie_file(filepath):
    """
    Creates a requests.cookies.RequestsCookieJar based
    on a firefox addon's cookie export feature.

    :param filepath: Path to cookies.json file.
    :return: requests.cookies.RequestsCookieJar
    """
    try:
        with open(filepath, 'r') as f:
            cookies_json = json.loads(f.read())
        jar = requests.cookies.RequestsCookieJar()
        if type(cookies_json) == dict:
            try:
                for cookie in cookies_json["cookies"]:
                    jar.set(cookie["name"], cookie["value"], domain=cookie["domain"],
                            path=cookie["path"], secure=cookie["secure"],
                            rest={'HttpOnly': cookie['httpOnly']})
                return jar
            except Exception as e:
                return None
        elif type(cookies_json) == list:
            try:
                for cookie in cookies_json:
                    jar.set(cookie["name"], cookie["value"], domain=cookie["domain"],
                    path=cookie["path"], secure=cookie["secure"],
                    rest={'HttpOnly': cookie['httpOnly']})
                return jar
            except Exception as e:
                return None
    except Exception as e:
        return None

def max_pages(soup):
    """
    Determine the maximum number of search results.

    :param soup: BeautifulSoup object of Github search page.
    :return: int
    """
    pagination_div = soup.findAll("div", {"class": "pagination"})

    for tag in pagination_div:
        hyperlinks = tag.find_all("a")
        for a in hyperlinks:
            # print(a.get_text())
            if a.get_text() == "Next":
                return int(hyperlinks[hyperlinks.index(a) - 1].get_text())

    return 1


def normalize_url(domain):
    if "http://" not in domain and "https://" not in domain:
        domain = "https://" + domain
    if domain[-1] == "/":
        domain = domain[:-1]
    return domain

def strip_tags(content):
    """
    Fun little function to strip problematic tags from matches.

    :param content: String of a regex match from a Github search result.
    :return: str
    """
    tags = [
        "<em>",
        "</em>",
        "<span>",
        "</span>",
        "<span class=\"pl-pse\">",
    ]
    for tag in tags:
        content = content.replace(tag, "")
    return content


def parse_code_page(key, regex, flags, soup, base_url):
    """
    Given a search word (key) and regex value, search the Github
    search results page (soup) for the regex matching key.

    :param key: A search term.
    :param regex: A regex value that indicates a positive match.
    :param soup: A BeautifulSoup object of the Github search result page.
    :return: dict
    """
    results = {key: []}
    code_list_items = soup.findAll("div", {"class": "code-list-item"})
    # print("Items: {}".format(len(code_list_items)))
    i = 0
    for item in code_list_items:
        path = ""
        # divs = item.findAll("div", {"class": "d-inline-block col-10"})
        divs = item.findAll("div", {"class": "file-box blob-wrapper"})
        i += 1
        # print("On item: {}, fileboxes: {}".format(i, len(divs)))
        for d in divs:
            path = d.find("a").get("href")
            code_blobs = d.findAll("td", {"class":"blob-code blob-code-inner"})
            # print(len(code_blobs))
            for blob in code_blobs:
                blob_code = strip_tags(blob.decode_contents())
                if flags:
                    regex_object = re.compile(regex, flags)
                else:
                    regex_object = re.compile(regex)
                search = regex_object.search(blob_code)
                # print("Regex: {}".format(regex))
                # print("Search results: {}".format(len(search)))
                # if "bindpw" in blob_code:
                #     print(blob_code)
                if search:
                    url = base_url + path
                    secret = search[0]
                    print_success("Found potential {}: {}".format(key, secret))
                    search_item = {
                        "url": url,
                        "snippet": blob_code,
                        "value": secret
                    }
                    results[key].append(search_item)
    return results

def write_results(results, outfile):
    header = "########################################"
    with open(outfile, "w") as f:
        for regex, items in results.items():
            spaces_count = len(header) - len(regex) - 4
            f.write(header + "\n")
            f.write("# " + " " * int(spaces_count / 2) + regex + " " * int(spaces_count / 2) + " #\n")
            f.write(header + "\n\n")
            for item in items:
                f.write("URL: {}\n".format(item["url"]))
                f.write("Value: {}\n".format(item["value"]))
                f.write("Snippet: {}\n\n".format(item["snippet"]))
                f.write("-" * 20)
                f.write("\n\n")
    print_success("[+] Results written to {}".format(outfile))

def build_regex(query):
    """
    Return a compiled regex object to perform search functions on.

    args:
        query (dict): Dictionary with "regex" and "flags" keys, where
                      "regex" is the regex to compile, and "flags" is
                      any compilation flags you'd like to include.
    returns:
        regular expression object to perform search and match functions on.
    """
    if query["flags"]:
        term = re.compile(query['regex'], query['flags'])
    else:
        term = re.compile(query['regex'])
    return term

def build_url(base_url, query):
    """
    Builds a github search url based on the query dictionary.
    For formatting of the query dictionary and a full list of
    supported parameters, please see regexes.py.

    args:
        normalized_url (str): Github URL that's already been sanitized
                              via normalize_url function.
        query (dict)        : Dictionary containing keys and search settings for the github url.

    returns:
        string URL to fetch.
    """
    # "/search?o=desc&p={}&q={}&s=indexed&type=Code"
    path = "/search?o=desc&s=indexed&type=Code".format(query["search_term"])
    query_string = "\"{}\"".format(query["search_term"])
    if query["language"]:
        path += "&l={}".format(query["language"])
    if query["inpath"]:
        query_string += "%20in:path"
    if query["infile"]:
        query_string += "%20in:file"
    if query["filename"]:
        query_string += "%20filename:{}".format(query["filename"])
    if query["extension"]:
        query_string += "%20extension:{}".format(query["extension"])
    path += "&q={}".format(query_string)
    path += "&p={}"
    url = base_url + path
    # print(colored("[DEBUG] Built search url: {}".format(url), "blue"))
    return base_url + path

def trufflehog_user(base_url, user, session):
    user_url = base_url + user
    print_info("Fetching user repositories from: {}".format(user_url))
    repo_url = user_url + "?tab=repositories"
    r = session.get(repo_url)
    soup = BeautifulSoup(r.content, 'html.parser')
    repo_list = soup.find("div", {"class": "org-repos repo-list"})

    th_dir = "trufflehog/"
    outdir = th_dir + user
    num_pages = max_pages(soup)
    try:
        os.mkdir(th_dir)
    except Exception as e:
        # print(e)
        pass
    try:
        os.mkdir(outdir)
    except Exception as e:
        pass 

    global max_threads, cur_threads
    print_info("Number of repository pages: {}".format(num_pages))
    for i in range(1, num_pages+1):
        r = session.get(repo_url + "&page={}".format(i))
        soup = BeautifulSoup(r.content, 'html.parser')
        hrefs = parse_repo_links(soup, user_url)
        for href in hrefs:
            while True:
                if cur_threads < max_threads:
                    t = Thread(target=git_clone, args=(href,))
                    cur_threads += 1
                    t.start()
                    break
                sleep(5)
        while cur_threads != 0:
            print_debug("Number of threads still cloning: {}".format(cur_threads))
            sleep(5)
        new_repos = find_local_repos()
        for repo in new_repos:
            while True:
                if cur_threads < max_threads:
                    t = Thread(target=trufflehog, args=(repo, outdir))
                    cur_threads += 1
                    t.start()
                    break
                sleep(5)
        while cur_threads != 0:
            print_debug("Number of threads still trufflehoggin': {}".format(cur_threads))
            sleep(10)
        del_repos(new_repos)



def crawl_github(base_url, session, query_list=queries, results_file = ""):
    """
    Crawl github for interesting things!

    :param base_url - string of a normalized Github URL with no trailing slash.
    :param session  - requests.Session object to use for the reqeusts.
    :param results_file - string of file to write results to.
    """
    results = {x['search_term']: [] for x in query_list}

    for query in query_list:
        regex_term = build_regex(query)
        search_url = build_url(base_url, query)
        try:
            print_debug("Fetching {}".format(search_url.format(1)))
            r = session.get(search_url.format(1))
            soup = BeautifulSoup(r.content, 'html.parser')
            with open(query["search_term"] + ".html", "wb") as f:
                f.write(r.content)
            max_len = max_pages(soup)
            if max_len == 100:
                print_warning("Excessive number of results (> 100 pages) returned for \"{}\".".format(query['search_term']))
            else:
                print_info("{} of search results found for \"{}\".".format(colored("[+] {} pages".format(max_len), "green"), query['search_term']))
            search_results = parse_code_page(query["search_term"], query["regex"], query["flags"], soup, base_url)
            results[query["search_term"]] += search_results[query["search_term"]]
            for i in range(2, max_len + 1):
                print_debug("On page: {}".format(i))
                try:
                    url = search_url.format(i)
                    r = session.get(url)
                    soup = BeautifulSoup(r.content, 'html.parser')
                    search_results = parse_code_page(query["search_term"], query["regex"], query['flags'], soup, base_url)
                    results[query["search_term"]] += search_results[query["search_term"]]
                except Exception as e:
                    print_error("Problem while iterating through search results: {}".format(e))
             
        except Exception as e:
            print_error("Problem occurred while cycling through regexes: {}".format(e))
    # print(results)
    for k in results.keys():
        print_success("Found {} {}s".format(len(results[k]), k))
    if results_file:
        write_results(results, results_file)

def main():
    parser = OptionParser()
    parser.add_option("-g", "--github_url", dest="github_url", help="URL of the Github server in quesiton.")
    parser.add_option("-c", "--cookies", dest="cookies", default="", help="Cookies file in JSON format.")
    parser.add_option("-u", "--user", dest="github_user", default="", help="User of repositories you wish to clone and run trufflehog on.")
    parser.add_option("-s", "--search", dest="search", default="all", help="Comma separated list of search terms from regexes.py to search for. By default, searches all. Otherwise, can be one or more of: {}".format(", ".join([x['search_term'] for x in queries])))
    parser.add_option("-o", "--outfile", dest="outfile", default="search_results.txt", help="Outfile to write search results to. This is not used when -u is passed. Default is \"search_results.txt\"")
    (options, args) = parser.parse_args()
    
    if not options.github_url:
        raise Exception("Require -g (--github_url) to be passed as a base URL to search from.")
    s = requests.Session()
    if options.cookies:
        jar = parse_cookie_file(options.cookies)
        if jar:
            s.cookies.update(jar)
        else:
            print_warning("No cookies could be parsed from \"{}\". Will attempt to continue without credentials.".format(options.cookies))

    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0"
    }
    s.headers.update(headers)
    base_url = normalize_url(options.github_url)
    
    # Logic for determining what "mode" we're in, either truffleHog or
    # Github crawling.
    if options.github_user:
        # Do the truffleHog dance.
        trufflehog_user(base_url, options.github_user, s)
    else:
        # Validate the search terms.
        if options.search == "all":
            crawl_github(base_url, s, queries, options.outfile)
        else:
            choices = [x.strip() for x in options.search.split(",")]
            query_list = [x for x in queries if x['search_term'] in choices]
            if query_list:
                print_info("Searching for key-word phrases: {}".format(",".join([x['search_term'] for x in query_list])))
                crawl_github(base_url, s, query_list, options.outfile)
            else:
                print_error("[ERROR] Could not parse any choices from the list you provided. Please see the help menu for valid choices.")
                
            

if __name__ == "__main__":
    main()
