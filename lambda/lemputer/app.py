import pygal

from chalice import Chalice

app = Chalice(app_name='lemputer')


line_chart = pygal.Line(width=500, height=400)
line_chart.add('A', [1, 3,  5, 16, 13, 3,  7])

graph = line_chart.render_data_uri()

test_html = """    <div id="graph_panel">
      <embed type="image/svg+xml" src={0} width=600 height=500>
    </div>""".format(graph)


@app.route('/')
def index():
    return {'title': 'Chalice with PyGal', 'body': test_html}
