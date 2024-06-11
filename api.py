import requests
import json
from datetime import datetime, timedelta
from uuid import uuid4

requests.packages.urllib3.disable_warnings()
import sys
import logging

logging.basicConfig(
    level=logging.DEBUG,
    format='%(levelname) -5s %(asctime) -5s %(name) -30s %(funcName) -20s %(lineno) -5d: %(message)s',
    stream=sys.stdout  # Redirect logs to stdout
)

logger = logging.getLogger(__name__)

# DOC
# https://opfab.github.io/documentation/current/getting_started/
# https://opfab.github.io/documentation/current/api/users/
# https://opfab.github.io/documentation/current/api/cards/
# https://opfab.github.io/documentation/current/api/businessconfig/
# https://opfab.github.io/documentation/current/api/external-devices/

def auth(func):
    def wrapper(self, *args, **kwargs):
        self._get_auth_token(self)
        return func(self, *args, **kwargs)

    return wrapper


class Severity:
    """The severity is a core principe of the OperatorFabric Card system. There are 4 severities available. A color is associated in the GUI to each severity. Here the details about severity and their meaning for OperatorFabric:

        ALARM: represents a critical state of the associated process, need an action from the operator. In the UI, the card is red;

        ACTION: the associated process need an action form operators in order to evolve correctly. In the UI, the card is orange;

        COMPLIANT: the process related to the card is in a compliant status. In the UI, the card is green.;

        INFORMATION: give information to the operator. In the UI, the card is blue."""

    Alarm = "ALARM"
    Action = "ACTION"
    Compliant = "COMPLIANT"
    Information = "INFORMATION"


class PublisherType:
    """Publisher type (publisherType)
        EXTERNAL - The sender is an external service
        ENTITY - The sender of the card is the user on behalf of the entity"""
    External = "EXTERNAL"
    Entity = "ENTITY"


class RepresentativeType:
    """Representative Type (representativeType)
    EXTERNAL - The representative is an external service
    ENTITY - The representative is an entity"""
    External = "EXTERNAL"
    Entity = "ENTITY"


class OperatorFabricClient:
    def __init__(self, server_url, username, password, token_endpoint_url=None, client_id="opfab-client", client_secret=None, grant_type="password"):
        self.server_url = server_url
        self.username = username
        self.password = password
        # TODO if not set, set to default opfab auth endpoint
        self.token_endpoint_url = token_endpoint_url
        self.grant_type = grant_type
        self.client_id = client_id
        self.client_secret = client_secret
        self.auth_token = None
        self.token_expiration = None

    def _get_auth_token(self):
        """Request token to be used with other calls"""
        now = datetime.now()
        if not self.auth_token or now > self.token_expiration:

            query_payload = {
                "username": self.username,
                "password": self.password,
                "grant_type": self.grant_type,
                "client_id": self.client_id,
                "client_secret": self.client_secret
            }

            token_response = requests.post(self.token_endpoint_url, data=query_payload, verify=False).json()
            logger.debug(token_response)

            if token_response and 'access_token' in token_response:
                self.auth_token = token_response['access_token']
                self.token_expiration = now + timedelta(seconds=token_response.get('expires_in', 3600))

        return self.auth_token

    def _get_headers(self):
        self._get_auth_token()
        return {
            'Content-type': 'application/json',
            'Authorization': f'Bearer {self.auth_token}'
        }

    def get_processes(self):
        query_url = '/businessconfig/processes'
        response = requests.get(f'{self.server_url}{query_url}', headers=self._get_headers(), verify=False)
        logger.debug(response)
        return response.json() if response.ok else None

    def get_monitoring(self):
        query_url = '/businessconfig/monitoring'
        response = requests.get(f'{self.server_url}{query_url}', headers=self._get_headers(), verify=False)
        logger.debug(response)
        return response.json() if response.ok else None

    def get_users(self):
        query_url = '/users/users'
        response = requests.get(f'{self.server_url}{query_url}', headers=self._get_headers(), verify=False)
        logger.debug(response, response.content)
        return response.json() if response.ok else None

    def create_perimeter(self, perimeter_id="example1-Perimeter", process="defaultProcess",
                         state_rights=[{"state": "messageState", "right": "Receive"}]):

        query_payload = {
            "id": perimeter_id,
            "process": process,
            "stateRights": state_rights
        }

        query_url = "/users/perimeters"
        response = requests.post(f"{self.server_url}{query_url}", json=query_payload, headers=self._get_headers(), verify=False)

        if not response.ok:
            logger.error("No Perimeter created")
            logger.debug(f"Response: {response.__dict__}")
            logger.debug(f"Request: {response.request.__dict__}")

        return response.json() if response.ok else None

    def set_perimeter_groups(self, perimeter_id="example1-Perimeter", groups=["Dispatcher"]):

        query_payload = groups

        query_url = f"/users/perimeters/{perimeter_id}/groups"
        response = requests.put(f"{self.server_url}{query_url}", json=query_payload, headers=self._get_headers(), verify=False)

        return response.json() if response.ok else None

    def send_card(self,
                  publisher="message-publisher",
                  process="defaultProcess",
                  process_version="2",
                  process_instance_id=None,
                  state="messageState",
                  severity="INFORMATION",
                  start_date=None,
                  summary="defaultProcess.summary",
                  title="defaultProcess.title",
                  data={"message": "Hello World !!! That's my first message"},
                  end_date=None,
                  tags=None,
                  entity_recipients=None,
                  group_recipients=None,
                  user_recipients=None,
                  last_time_to_decide=None,
                  seconds_before_time_span_for_reminder=None
                  ):

        """
        ### Mandatory ###

        Publisher (publisher)
        The publisher field bears the identifier of the emitter of the card, be it an entity or an external service.

        Process (process)
        This field indicates which process the card is attached to. This information is used to resolve the presentation resources (bundle) used to render the card and card details.

        Process Version (process_version)
        The rendering of cards of a given process can evolve over time. To allow for this while making sure previous cards remain correctly handled, OperatorFabric can manage several versions of the same process. The processVersion field indicate which version of the process should be used to retrieve the presentation resources (i18n, templates, etc.) to render this card.

        Process Instance Identifier (process_instance_id)
        A card is associated to a given process, which defines how it is rendered, but it is also more precisely associated to a specific instance of this process. The processInstanceId field contains the unique identifier of the process instance.

        State in the process (state)
        The card represents a specific state in the process. In addition to the process, this information is used to resolve the presentation resources used to render the card and card details.

        Start Date (start_date)
        Start date of the active period of the card (process business time).

        Severity (severity)
        The severity is a core principe of the OperatorFabric Card system. There are 4 severities available. A color is associated in the GUI to each severity. Here the details about severity and their meaning for OperatorFabric:

            ALARM: represents a critical state of the associated process, need an action from the operator. In the UI, the card is red;

            ACTION: the associated process need an action form operators in order to evolve correctly. In the UI, the card is orange;

            COMPLIANT: the process related to the card is in a compliant status. In the UI, the card is green.;

            INFORMATION: give information to the operator. In the UI, the card is blue.

        Title (title)
        This attribute is display as header of a card in the feed of the GUI. It’s the main User destined Information of a card. The value refer to an i18n value used to localize this information.

        Summary (summary)
        This attribute is display as a description of a card in the feed of the GUI, when the card is selected by the operator. It’s completing the information of the card title. The value refer to an i18n value used to localize this information.

        ### Optional ###

        End Date (endDate)
        End date of the active period of the card (process business time).

        Tags (tag)
        Tags are intended as an additional way to filter cards in the feed of the GUI.

        EntityRecipients (entityRecipients)
        Used to send cards to entity : all users members of the listed entities who have the right for the process/state of the card will receive it.

        GroupRecipients (groupRecipients)
        Used to send cards to groups : all users members of the groups will receive it. If this field is used in conjunction with entityRecipients, to receive the cards :

        users must be members of one of the entities AND one of the groups to receive the cards.

        OR

        users must be members of one of the entities AND have the right for the process/state of the card.

        UserRecipients (userRecipients)
        Used to send cards directly to users without using groups or entities for card routing.

        Last Time to Decide (lttd)
        Fixes the moment until when a response is possible for the card. After this moment, the response button won’t be useable. When lttd time is approaching, a clock is visible on the card in the feed with the residual time. The lttd time can be set for cards that don’t expect any response

        SecondsBeforeTimeSpanForReminder (secondsBeforeTimeSpanForReminder)
        Fixes the time for remind before the event define by the card see Card reminder

        ToNotify (toNotify)
        Boolean attribute. If the card must not be displayed in the feed and in monitoring screen, this field must be set to false. In that case, it means the card is stored only in archivedCards collection and not in cards collection.

        Publisher type (publisherType)
            EXTERNAL - The sender is an external service

            ENTITY - The sender of the card is the user on behalf of the entity

        Representative (representative)
        Used in case of sending card as a representative of an entity or a publisher (unique ID of the entity or publisher)

        Representative Type (representativeType)
        EXTERNAL - The representative is an external service

        ENTITY - The representative is an entity

        """

        severities = {
            "ALARM": "Represents a critical state of the associated process, need an action from the operator. In the UI, the card is red.",
            "ACTION": "The associated process need an action form operators in order to evolve correctly. In the UI, the card is orange.",
            "COMPLIANT": "The process related to the card is in a compliant status. In the UI, the card is green.",
            "INFORMATION": "Give information to the operator. In the UI, the card is blue"}

        if severity not in severities.keys():
            logger.error(f"{severity} not in {severities.keys()}")
            logger.info(f"Severity usage: {severities}")
            return None

        query_payload = {
            "publisher": publisher,
            "process": process,
            "processVersion": process_version,
            "processInstanceId": process_instance_id,
            "state": state,
            "severity": severity,
            "summary": {"key": summary},
            "title": {"key": title}
        }

        if type(summary) == dict:
            query_payload["summary"] = summary
        elif type(summary) == str:
            query_payload["summary"] = {"key": summary}

        if type(title) == dict:
            query_payload["title"] = title
        elif type(title) == str:
            query_payload["title"] = {"key": title}

        if not start_date:
            query_payload["startDate"] = datetime_to_unix_ms(datetime.now())
        else:
            query_payload["startDate"] = datetime_to_unix_ms(start_date)

        if not process_instance_id:
            query_payload["processInstanceId"] = str(uuid4())

        # Add optional fields
        # TODO - currently only some fields are supported

        if data:
            if type(data) == dict:
                query_payload["data"] = json.loads(json.dumps(data, default=str))  # Make sure it is json serialisable
            elif type(data) == str:
                query_payload["data"] = {"message": data}

        if end_date:
            query_payload["endDate"] = datetime_to_unix_ms(end_date)

        if entity_recipients and type(entity_recipients) == list:
            query_payload["entityRecipients"] = entity_recipients

        if group_recipients and type(group_recipients) == list:
            query_payload["groupRecipients"] = group_recipients

        if user_recipients and type(user_recipients) == list:
            query_payload["userRecipients"] = user_recipients

        if not entity_recipients and not user_recipients and not group_recipients:
            query_payload["groupRecipients"] = ["Dispatcher"]

        if tags and type(tags) == list:
            query_payload["tags"] = tags

        if last_time_to_decide:
            query_payload["lttd"] = datetime_to_unix_ms(last_time_to_decide)

        if seconds_before_time_span_for_reminder:
            query_payload["secondsBeforeTimeSpanForReminder"] = int(seconds_before_time_span_for_reminder)

        logger.debug(json.dumps(query_payload, indent=4))

        query_url = "/cards/cards"
        response = requests.post(f"{self.server_url}{query_url}", json=query_payload, headers=self._get_headers(), verify=False)



        return response.json() if response.ok else logger.error(response.content)

