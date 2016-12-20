import pygal
import boto3

from chalice import Chalice

# Globals
DOMAIN_NAME = "test_db"     # This will likely stay fixed
SENSOR = "TC_External"      # This will likely be passed in with the request

# Setup web app
app = Chalice(app_name='lemputer')

# Create chart
line_chart = pygal.Line(width=500, 
                        height=400, 
                        title=SENSOR.
                        x_label_rotation=90)

# Get sensor data from 
client = boto3.client("sdb")
get_resp = client.select(SelectExpression="SELECT " + SENSOR + \
                                          " FROM " + DOMAIN_NAME)

# Generate chart and HTML data from SDB data
data_str = str()
values = list()
labels = list()
for attribs in get_resp['Items']:
    data_str = data_str + attribs['Name'] + "<br>"

    for data in attribs['Attributes']:
         data_str = data_str + data['Name'] + " -- " + data['Value'] + "<br>"
         values.append(float(data['Value']))
         labels.append(attribs['Name'])

    data_str = data_str + "<br><br>"

# Populate chart
line_chart.add("data", values)
line_chart.x_labels = labels
graph = line_chart.render_data_uri()

# Generate HTML result
test_html = """    <div id="graph_panel">
      <embed type="image/svg+xml" src={0} width=600 height=500>
    </div>{1}""".format(graph, data_str)


@app.route('/')
def index():
    return {'title': 'Chalice with PyGal', 'body': test_html}
