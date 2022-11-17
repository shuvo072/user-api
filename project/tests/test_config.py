def test_development_config(test_app):
    test_app.config.from_object('project.user.config.DevelopmentConfig')
    assert test_app.config['SECRET_KEY'] == 'verysecretkey'
    assert not test_app.config['TESTING']
    assert test_app.config['SQLALCHEMY_DATABASE_URI'] == 'postgresql://postgres:shuvo72@localhost:5555/users'


def test_testing_config(test_app):
    test_app.config.from_object('project.user.config.TestingConfig')
    assert test_app.config['SECRET_KEY'] == 'verysecretkey'
    assert test_app.config['TESTING']
    assert not test_app.config['PRESERVE_CONTEXT_ON_EXCEPTION']
    assert test_app.config['SQLALCHEMY_DATABASE_URI'] == 'postgresql://postgres:shuvo72@localhost:5555/users_test'


def test_production_config(test_app):
    test_app.config.from_object('project.user.config.ProductionConfig')
    assert test_app.config['SECRET_KEY'] == 'verysecretkey'
    assert not test_app.config['TESTING']
    assert test_app.config['SQLALCHEMY_DATABASE_URI'] == 'postgresql:///example'