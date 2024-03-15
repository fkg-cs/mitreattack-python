from flask import Flask, render_template, url_for

from Janus.controller.group_page_controller import index_group_info
from Janus.controller.CTI_groups_page_controller import index_CTI_groups
from Janus.controller.matrix_enterprise_page_controller import index_enterprise_matrix
from Janus.controller.matrix_ics_page_controller import index_ics_matrix
from Janus.controller.matrix_mobile_page_controller import index_mobile_matrix
from Janus.controller.technique_page_controller import index_technique_info

app = Flask(__name__, static_folder=r'..\Janus\static',template_folder=r'..\Janus\view')
@app.route('/')
def home_page():
    return render_template("home.html")
@app.route('/matrix_selector')
def matrix_selector_page():
    return render_template("matrix_selector.html")
@app.route('/matrix_enterprise')
def matrix_enterprise():
    return render_template("matrix_page.html", output_list=index_enterprise_matrix())

@app.route('/matrix_ics')
def matrix_ics():
    return render_template("matrix_page.html", output_list=index_ics_matrix())
@app.route('/matrix_mobile')
def matrix_mobile():
    return render_template("matrix_page.html", output_list=index_mobile_matrix())

@app.route('/techniques/<id>', methods=['GET'])
def technique_details(id):
    return render_template("technique_page.html", output_list=index_technique_info(id))

@app.route('/CTI_groups')
def tree_groups():
    return render_template("CTI_groups.html", output_list=index_CTI_groups())
@app.route('/CTI_groups/<id>', methods=['GET'])
def group_details(id):
    return render_template("group_page.html", output_list=index_group_info(id))
if __name__ == "__main__":
    app.run()