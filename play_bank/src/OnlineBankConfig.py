from playground import Configure
import os, configparser

# TODO: There's already a playground class like this. Merge
# Unify playground config area with a general configuration system

    
class OnlineBankConfig:
    def __init__(self, create=True, view=None):
        if view != None and create:
            raise Exception("View has no file access and does not create")
        
        self._view = view
        if not self._view:
            playgroundPath = Configure.CurrentPath()
            self._path = os.path.join(playgroundPath, "bank")
            self._config_file = os.path.join(self._path, "config.ini")
            if not os.path.exists(self._path):
                if create:
                    os.mkdir(self._path)
                else:
                    raise Exception("No path for bank config")
            self.reloadConfig()
        else:
            self._path = view.path()
            self._config = configparser.ConfigParser()
            self._config.update(self._view._config)
                
    def path(self):
        return self._path
        
    def reloadConfig(self):
        if self._view: return
        self._config = configparser.ConfigParser()
        self._config.read(self._config_file)
        
    def saveConfig(self):
        if self._view: return
        with open(self._config_file, 'w') as configfile:
            self._config.write(configfile)
        
    def set_parameter(self, section, key, value):
        self.reloadConfig()
        #section,param = args.setting.split(":")
        section = section.upper()
        if section not in self._config:
            self._config[section] = {}
        self._config[section][key] = value
        self.saveConfig()
        
    def get_parameter(self, section, key, default=None):
        self.reloadConfig()
        if section not in self._config or key not in self._config[section]:
            return default
        return self._config[section][key]
        
    def has_section(self, section):
        self.reloadConfig()
        return section in self._config
        
    def has_key(self, section, key):
        self.reloadConfig()
        return section in self._config and key in self._config[section]
        
    def create_view(self):
        return OnlineBankConfig(view=self, create=False)