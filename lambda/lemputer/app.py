import pygal
import boto3

from chalice import Chalice

# Testing Globals
# DOMAIN_NAME = "test_db"
# SENSOR = "TC_External"

# Setup web app
app = Chalice(app_name='lemputer')
client = boto3.client("sdb")


@app.route('/{device}/{sensor}', methods=['GET'])
def index(device, sensor):
    # Create chart
    line_chart = pygal.Line(width=500, 
                            height=400, 
                            title=sensor,
                            x_label_rotation=90)

    # Get sensor data from 
    get_resp = client.select(SelectExpression="SELECT " + sensor + \
                                              " FROM " + device)

    # Generate chart and HTML data from SDB data
    data_str = str()
    values = list()
    labels = list()
    for attribs in get_resp['Items']:
        data_str = data_str + attribs['Name'] + "<br>"

        for data in attribs['Attributes']:
             data_str = data_str + data['Name'] + " -- " + data['Value'] + "<br>"
             values.append(float(data['Value']))
             labels.append(attribs['Name'].split("T")[1])

        data_str = data_str + "<br><br>"

    # Populate chart
    line_chart.add("temp (C)", values)
    line_chart.x_labels = labels
    graph = line_chart.render_data_uri()

    # Generate HTML result
    test_html = """    <div id="graph_panel">      
<embed type="image/svg+xml" src={0} width=600 height=500>
</div>""".format(graph)


    return {'title': 'Chalice with PyGal', 'body': test_html}


@app.route('/{device}', methods=['POST'])
def input(device):
    json_data = {}
    json_data['input'] = app.current_request.json_body

    client.put_attributes(DomainName=device,
                          ItemName=json_data['input']['date'],
                          Attributes=[{'Name': json_data['input']['sensor'],
                                       'Value': str(json_data['input']['value'])}])

    return(device + " -- " + str(json_data))


@app.route('/{device}/{sensor}/purge', methods=['POST'])
def input(device, sensor):
    json_data = {}
    json_data['input'] = app.current_request.json_body

    # Check that a purge value has been posted
    if 'purge' in json_data['input']:
        results = client.select(SelectExpression="SELECT " + sensor + \
                                                " FROM " + device)

        for item in results['Items']:
            # Convert name to date object
            item_date = datetime.datetime.strptime(item['Name'], '%Y-%m-%dT%H:%M:%S')

            # Delete item if older than a day
            if item_date < datetime.datetime.now() - datetime.timedelta(days=1):
                client.delete_attributes(DomainName=device,
                                         ItemName=item['Name'],
                                         Attributes=item['Attributes'])

    return(device + " -- " + str(json_data))
