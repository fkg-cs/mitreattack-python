from flask import Flask, render_template

from Janus.controller.group_page import get_group_info
from Janus.controller.groups_tree_page import get_groups_list
from Janus.controller.matrix_enterprise_page import get_enterprise_matrix
from Janus.controller.matrix_ics_page import get_ics_matrix
from Janus.controller.matrix_mobile_page import get_mobile_matrix
from Janus.controller.technique_page import get_technique_info

app = Flask(__name__, static_folder=r'..\Janus\static',template_folder=r'..\Janus\templates')
@app.route('/')
def home_page():
    return render_template("home.html")
@app.route('/matrix_selector')
def matrix_selector_page():
    return render_template("matrix_selector.html")
@app.route('/matrix_enterprise')
def matrix_enterprise():
    return render_template("matrix_template.html", output_list=get_enterprise_matrix())

@app.route('/matrix_ics')
def matrix_ics():
    return render_template("matrix_template.html", output_list=get_ics_matrix())
@app.route('/matrix_mobile')
def matrix_mobile():
    return render_template("matrix_template.html", output_list=get_mobile_matrix())

@app.route('/techniques/<id>', methods=['GET'])
def technique_details(id):
    return render_template("technique_template.html", output_list=get_technique_info(id))

@app.route('/CTI_groups')
def tree_groups():
    return render_template("groups_tree_template.html", output_list=get_groups_list())
@app.route('/CTI_groups/<id>', methods=['GET'])
def group_details(id):
    return render_template("group_template.html", output_list=get_group_info(id))
if __name__ == "__main__":
    app.run()