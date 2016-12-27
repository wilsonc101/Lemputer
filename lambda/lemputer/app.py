import pygal
import boto3
import datetime

from chalice import Chalice

KNOWN_DEVICES = ['lemon']     # Should be in a DB but not yet...

# Setup web app
app = Chalice(app_name='lemputer')
client = boto3.client("sdb")


@app.route('/{device}/{sensor}', methods=['GET'])
def index(device, sensor):
    # Create chart
    line_chart = pygal.Line(width=500, 
                            height=400, 
                            title=sensor,
                            x_label_rotation=90,
                            x_labels_major_count=16,
                            show_minor_y_labels=True,
                            show_minor_x_labels=False,
                            show_only_major_dots=True,
                            dots_size=3,
                            font_family="Arial, Helvetica, sans-serif")

    # Get sensor data from 
    get_resp = client.select(SelectExpression="SELECT " + sensor + \
                                              " FROM " + device)

    # Generate chart and HTML data from SDB data
    values = list()
    labels = list()
    for attribs in get_resp['Items']:

        for data in attribs['Attributes']:
             values.append(float(data['Value']))
             labels.append(attribs['Name'].split("T")[1])

    # Populate chart
    line_chart.add("temp (C)", values)
    line_chart.x_labels = labels
    graph = line_chart.render_data_uri()

    # Generate HTML result
    html_body = """    <div id="graph_panel">      
<embed type="image/svg+xml" src={0} width=600 height=500>
</div>""".format(graph)

    return {'title': 'Lemputer - ' + device, 
            'body': html_body}


@app.route('/{device}', methods=['POST'])
def input(device):
    device = str(device)

    json_data = {}
    json_data['input'] = app.current_request.json_body
        
    # Check the device is known to us
    if device not in KNOWN_DEVICES:
        raise BadRequestError("Unknown Device")

    try:
        # Fix types
        record_date = json_data['input']['date']
        str_purge = str(json_data['input']['purge'])
        purge = eval(json_data['input']['purge'])
        data = list(json_data['input']['data'])
    except:
        raise BadRequestError("Bad data")

    try:
        # Loop through posted list, fix types - must be strings for SDB
        corrected_data = list()
        for i in data:
            data_section = dict()
            data_section['Name'] = str(i['Name'])
            data_section['Value'] = str(i['Value'])
            corrected_data.append(data_section)

        client.put_attributes(DomainName=device,
                              ItemName=record_date,
                              Attributes=corrected_data)
    except:
        raise BadRequestError("Failed to write to database")


    # If purge requests, clear items older than 1 day
    if purge:
        results = client.select(SelectExpression="SELECT *" + \
                                                " FROM " + device)

        for item in results['Items']:
            # Convert name to date object
            item_date = datetime.datetime.strptime(item['Name'], '%Y-%m-%dT%H:%M:%S')

            # Delete item if older than a day
            if item_date < datetime.datetime.now() - datetime.timedelta(days=1):
                client.delete_attributes(DomainName=device,
                                         ItemName=item['Name'],
                                         Attributes=item['Attributes'])
    

    return(str({device: "done"}))


