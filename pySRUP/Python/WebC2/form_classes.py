from flask_wtf import FlaskForm
from wtforms import SubmitField, SelectField
from wtforms.validators import data_required


class ActionForm(FlaskForm):
    device = SelectField("Device ID:", validators=[data_required()])
    action_type = SelectField("Action type:", choices=[("START", "START"), ("STOP", "STOP")])
    submit = SubmitField('Submit')


class JoinForm(FlaskForm):
    accept = SubmitField('Accept Join Request')
    reject = SubmitField('Reject Join Request')

