
SOAR Platform Documentation

Title: SOAR Platform  – Wazuh, Shuffle, and TheHive

Introduction:
This document outlines the complete setup process for a Security Orchestration, Automation, and Response (SOAR) platform using Wazuh for detection, Shuffle for orchestration, and TheHive for case management. It includes installation steps, configuration notes, and integration walkthroughs for seamless alert handling and automation.





Wauzh Install & agent Deployment

*Note: always stay in root in terminal



Sudo su to root

1. Sudo apt install default-jdk -y
2.curl -sO https://packages.wazuh.com/4.11/wazuh-install.sh 
3.sudo bash wazuh-install.sh -a












Add this port to use your tools web page in your base OS from Virtual Machine



Now Add the agent click on the Deploy new agent on dashboard



Select the agent OS which agent runs 



Put the server address like host website name or IP address or domain name here I have given IP of machine which it is running 



Add agent Name and groups 

Use this commands on respective terminal or cmd by giving administrative privilege or root privilege





Shuffle Install

Do this to avoid pip error in ubuntu 

Sudo apt installl pip
Step 1: Update Your System
Before installing Shuffle, update your system:
sudo apt update && sudo apt upgrade -y

Step 2: Install Docker & Docker Compose
Shuffle runs in Docker containers, so you'll need Docker and Docker Compose:
sudo apt install -y docker.io docker-compose
Enable and start Docker:
sudo systemctl enable --now docker
Check if Docker is running:
docker --version

Step 3: Clone the Shuffle Repository
Download the Shuffle source code from GitHub:
git clone https://github.com/frikky/Shuffle.gitcd Shuffle

Change the port in docker-compose.yml(if you are running all tools in one vm or server)  change this ports to not conflict with wazuh

9200:9200 to 9201:9200


Note: If You use Ubuntu desktop install the pip before the compse or you might get error

Next type docker-compose up -d



You can see your password here
sudo nano wazuh-install-files/wazuh-passwords.txt

If you are using the vm don’t forgot to add port forwarding 



TheHive Installation 

Step 1: Update the System
sudo apt-get update && sudo apt-get upgrade -y
🔹 Step 2: Install Dependencies
sudo apt-get install \
  ca-certificates \
  curl \
  gnupg \
  lsb-release -y

🔹 Step 3: Add Docker Repository
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
  sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] \
  https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

🔹 Step 4: Install Docker
sudo apt-get update
sudo apt-get install docker-ce docker-ce-cli containerd.io docker-compose-plugin -y

🔹 Step 5: Verify Docker Installation
sudo systemctl status docker
You should see it as "active (running)". Press q to exit the status view.











🔹 Step 6: Pull TheHive Docker Image
sudo docker pull strangebee/thehive:5.4

NANO APPLICATION.CONF 
kamon.metric {
 timers { 
dynamic-range { 
lowest-trackable-value =-1000000 # Adjust this to allow negative values highest-trackable-value = 3600000000000
 } 
} 
}
docker run-d \--name thehive \-p 9000:9000 \-v /home/shuffle/Shuffle/application.conf:/etc/thehive/application.conf \ strangebee/thehive:5.4
Use docker start/stop thehive to run or pause the hive 
Once Docker builds your containers point your browser to the WebUI:
http://***YOUR_IP***:9000

Default admin credentials are usesr: admin@thehive.local 
Pass: secret.



Click on + sign and add the organization


Click on the created Organizaation




Click again on + to add user 


Select service/normal in type for API in shuffle instance






The Shuffle and Wazuh workflow setup 

Go to Cd /var/ossec/intergrations/ create nano custom-shuffle add this

#!/bin/sh
# Created by Shuffle, AS. <frikky@shuffler.io>.WPYTHON_BIN="framework/python/bin/python3"SCRIPT_PATH_NAME="$0"DIR_NAME="$(cd $(dirname ${SCRIPT_PATH_NAME}); pwd -P)"
SCRIPT_NAME="$(basename ${SCRIPT_PATH_NAME})"case ${DIR_NAME} in
    */active-response/bin | */wodles*)
        if [ -z "${WAZUH_PATH}" ]; then
            WAZUH_PATH="$(cd ${DIR_NAME}/../..; pwd)"
        fi        PYTHON_SCRIPT="${DIR_NAME}/${SCRIPT_NAME}.py"
    ;;
    */bin)
        if [ -z "${WAZUH_PATH}" ]; then
            WAZUH_PATH="$(cd ${DIR_NAME}/..; pwd)"
        fi        PYTHON_SCRIPT="${WAZUH_PATH}/framework/scripts/${SCRIPT_NAME}.py"
    ;;
     */integrations)
        if [ -z "${WAZUH_PATH}" ]; then
            WAZUH_PATH="$(cd ${DIR_NAME}/..; pwd)"
        fi        PYTHON_SCRIPT="${DIR_NAME}/${SCRIPT_NAME}.py"
    ;;
esac
${WAZUH_PATH}/${WPYTHON_BIN} ${PYTHON_SCRIPT} "$@"Save it ctl+x
Also create nano custom-shuffle.py and add this
#!/usr/bin/env python3
# Created by Shuffle, AS. <frikky@shuffler.io>.
# Based on the Slack integration using Webhooksimport json
import sys
import time
import ostry:
    import requests
    from requests.auth import HTTPBasicAuth
except Exception as e:
    print("No module 'requests' found. Install: pip install requests")
    sys.exit(1)# ADD THIS TO ossec.conf configuration:
#  <integration>
#      <name>custom-shuffle</name>
#      <hook_url>http://<IP>:3001/api/v1/hooks/<HOOK_ID></hook_url>
#      <level>3</level>
#      <alert_format>json</alert_format>
#  </integration># Global vars
debug_enabled = False 
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
json_alert = {}
now = time.strftime("%a %b %d %H:%M:%S %Z %Y")# Set paths
log_file = '{0}/logs/integrations.log'.format(pwd)try:
    with open("/tmp/shuffle_start.txt", "w+") as tmp:
        tmp.write("Script started")
except:
    pass
def main(args):
    debug("# Starting")    # Read args
    alert_file_location = args[1]
    webhook = args[3]    debug("# Webhook")
    debug(webhook)    debug("# File location")
    debug(alert_file_location)    # Load alert. Parse JSON object.
    try:
        with open(alert_file_location) as alert_file:
            json_alert = json.load(alert_file)
    except:
        debug("# Alert file %s doesn't exist" % alert_file_location)    debug("# Processing alert")
    try:
        debug(json_alert)
    except Exception as e:
        debug("Failed getting json_alert %s" % e)
        sys.exit(1)    debug("# Generating message")
    msg = generate_msg(json_alert)
    if isinstance(msg, str):
        if len(msg) == 0:
            return
    debug(msg)    debug("# Sending message")    try:
        with open("/tmp/shuffle_end.txt", "w+") as tmp:
            tmp.write("Script done pre-msg sending")
    except:
        pass
    send_msg(msg, webhook)
def debug(msg):
    if debug_enabled:
        msg = "{0}: {1}\n".format(now, msg)
        print(msg)
        f = open(log_file, "a")
        f.write(msg)
        f.close()# Skips container kills to stop self-recursion
def filter_msg(alert):
    # These are things that recursively happen because Shuffle starts Docker containers
    skip = ["87924", "87900", "87901", "87902", "87903", "87904", "86001", "86002", "86003", "87932", "80710", "87929", "87928", "5710"]
    if alert["rule"]["id"] in skip:
        return False    #try:
    #    if "docker" in alert["rule"]["description"].lower() and "
    #msg['text'] = alert.get('full_log')
    #except:
    #    pass
    #msg['title'] = alert['rule']['description'] if 'description' in alert['rule'] else "N/A"    return Truedef generate_msg(alert):
    if not filter_msg(alert):
        print("Skipping rule %s" % alert["rule"]["id"])
        return ""    level = alert['rule']['level']    if (level <= 4):
        severity = 1
    elif (level >= 5 and level <= 7):
        severity = 2
    else:
        severity = 3    msg = {}
    msg['severity'] = severity 
    msg['pretext'] = "WAZUH Alert"
    msg['title'] = alert['rule']['description'] if 'description' in alert['rule'] else "N/A"
    msg['text'] = alert.get('full_log')
    msg['rule_id'] = alert["rule"]["id"]
    msg['timestamp'] = alert["timestamp"]
    msg['id'] = alert['id']
    msg["all_fields"] = alert    #msg['fields'] = []
    #    msg['fields'].append({
    #        "title": "Agent",
    #        "value": "({0}) - {1}".format(
    #            alert['agent']['id'],
    #            alert['agent']['name']
    #        ),
    #    })
    #if 'agentless' in alert:
    #    msg['fields'].append({
    #        "title": "Agentless Host",
    #        "value": alert['agentless']['host'],
    #    })    #msg['fields'].append({"title": "Location", "value": alert['location']})
    #msg['fields'].append({
    #    "title": "Rule ID",
    #    "value": "{0} _(Level {1})_".format(alert['rule']['id'], level),
    #})    #attach = {'attachments': [msg]}    return json.dumps(msg)
def send_msg(msg, url):
    debug("# In send msg")
    headers = {'content-type': 'application/json', 'Accept-Charset': 'UTF-8'}
    res = requests.post(url, data=msg, headers=headers, verify=False)
    debug("# After send msg: %s" % res)
if __name__ == "__main__":
    try:
        # Read arguments
        bad_arguments = False
        if len(sys.argv) >= 4:
            msg = '{0} {1} {2} {3} {4}'.format(
                now,
                sys.argv[1],
                sys.argv[2],
                sys.argv[3],
                sys.argv[4] if len(sys.argv) > 4 else '',
            )
            #debug_enabled = (len(sys.argv) > 4 and sys.argv[4] == 'debug')
            debug_enabled = True
        else:
            msg = '{0} Wrong arguments'.format(now)
            bad_arguments = True        # Logging the call
        try:
            f = open(log_file, 'a')
        except:
            f = open(log_file, 'w+')
            f.write("")
            f.close()        f = open(log_file, 'a')
        f.write(msg + '\n')
        f.close()        if bad_arguments:
            debug("# Exiting: Bad arguments. Inputted: %s" % sys.argv)
            sys.exit(1)        # Main function
        main(sys.argv)    except Exception as e:
        debug(str(e))
        raise


Next give the permision to this files 




Configure Wazuh to Forward Alerts to Shuffle
On the Wazuh server, edit the /var/ossec/etc/ossec.conf file.
Add the following <integration> block within the <ossec_config> section:​Wazuh+1Medium+1xml

  <integration>
    <name>shuffle</name>
    <hook_url>http://<SHUFFLE_IP>:3001/api/v1/hooks/<HOOK_ID></hook_url>
    <level>3</level>
    <alert_format>json</alert_format>
  </integration>
Replace <SHUFFLE_IP> and <HOOK_ID> with your actual Shuffle IP address and webhook ID. The below red circle is Shuffle_IP and HOOK_id  

The <level> tag specifies the minimum alert level to forward; adjust as needed.​Wazuh
Restart the Wazuh manager to apply changes:​Wazuh
  sudo systemctl restart wazuh-manager




Run to check for log generation as show in below




CREATING ALERT IN THE HIVE
Now open the hive and login with your new created user of new organisation

Select on profile and go to settings 

You will see option click on API and click on generate 

Click reveal to copy the API 

Add the API in the area field in thehive app in Shuffle As show below 

In the Red marked box You will see a Api input box and thehive url input box for first time user With ORANG BUTTON saying authenticate.
On the right panel where you're filling out Title, Tags, etc.
Click the “Advanced” tab (next to “Simple”).
{
  "description": "{{ '''data: $recivewazuhalert.all_fields.rule.description''' | replace: '\n', '\\r\\n' }}",
  "externallink": "",
  "flag": false,
  "pap": 2,
  "severity": 2,
  "source": "Wazuh",
  "sourceRef": "$recivewazuhalert.id",
  "status": "New",
  "summary": "data: $recivewazuhalert.all_fields.rule.description",
  "tags": ["Tag: $recivewazuhalert.timestamp"],
  "title": "Source IP: $recivewazuhalert.id",
  "tlp": 2,
  "type": "external"
}
Key Notes:
Tags is set as a JSON array ["..."] — this is important.
All strings are wrapped with "..." without escaping using \.
${} syntax is removed — Shuffle uses $stepname.field directly.
Make sure all the fields exist in the webhook output (you can test with the "play" icon in the step view).
Let me know if you want this version to dynamically pull more fields from the Wazuh alert.


Testing the Workflow

After Doing all this process you need to test the connectivity Click the run button on the Shuffle

Simulate Suspicious SSH Brute Force
You can safely simulate an alert by generating failed login attempts on agent VM or on your windows machin
this is for the agent ubuntu vm: for i in {1..10}; do ssh fakeuser@localhost; done

If you see case creation in the hive means it is working perfectly 
*Note*: From here on you can add the cortex to create and solve the case  automatically in thehive 
