'''
Created on Nov 22, 2013

@author: sethjn
'''

import logging
import inspect
import traceback


class InvalidErrorLevel(Exception):
    def __init__(self):
        Exception.__init__(self, "Level must be a tuple(uint, str)")


class DuplicateErrorLevelValue(Exception):
    def __init__(self, value):
        Exception.__init__(self, "Attempt to create an error level with the same value %d" % value)


class DuplicateErrorLevelName(Exception):
    def __init__(self, name):
        Exception.__init__(self, "Attempt to create an error level with the same name %s" % name)


class InvalidReporterName(Exception):
    def __init__(self):
        Exception.__init__(self, "Reporter names must be of the form x.y.z or just x")


class ErrorLevel(object):
    ValueMapping = {}
    NameMapping = {}
    
    def __init__(self, value, name):
        if value in self.ValueMapping:
            raise DuplicateErrorLevelValue(value)
        if name in self.NameMapping:
            raise DuplicateErrorLevelName(name)
        self.__value = value
        self.__name = name
        self.ValueMapping[value] = name
        self.NameMapping[name] = value
        
    def name(self): return self.__name

    def value(self): return self.__value

    def __str__(self): return self.__name

    def __int__(self): return self.__value

    def __cmp__(self, other): return self.__value - other.value()

    def __hash__(self): return hash(self.__value)

    
ErrorLevel.LEVEL_WARNING = ErrorLevel(0     , "Warning" )
ErrorLevel.LEVEL_REGULAR = ErrorLevel(1000  , "Regular" )
ErrorLevel.LEVEL_FATAL   = ErrorLevel(2000  , "Fatal"   )
    
ErrorLevel.STANDARD_LEVELS = [ErrorLevel.LEVEL_WARNING, ErrorLevel.LEVEL_REGULAR, ErrorLevel.LEVEL_FATAL]


class ErrorReporter(object):
    def __init__(self, name, parent=None):
        self.__name = name
        self.__parent = parent
        self.__children = {}
        self.__handlers = {}
        self.__reportingLevels = []
        self.__propagate = False
        
    def localName(self): return self.__name
    
    def name(self): return self.__parent and (self.__parent.name() + self.__name) or self.__name
    
    def propegate(self): return self.__propagate
    
    def setPropegation(self, onOff): self.__propagate = onOff
        
    def report(self, level, message, exception=None, stackOffset=0, explicitFrame=None):
        handled = False
        if explicitFrame:
            callerFrame = explicitFrame
        else:
            callerFrame = inspect.stack()[1+stackOffset] # 0 represents this function
                                            # 1 represents line at reporter
                                            # 2 represents the caller unless we were called from handleException
                                            # 3 represents the caller if there's an intermediate call from handleException
                                            # If other layers get inbetween the call to reportError, they should
                                            #   increase the stackHack
            callerFrame = callerFrame[0] # Get just the frame, not any of the line info
        result = None
        for repLevel in self.__reportingLevels:
            if repLevel <= level:
                try:
                    result = self.__handlers[repLevel].handle(self.name(), level, message, exception, callerFrame)
                except Exception as e:
                    result = e
                if isinstance(result,Exception):
                    break
                else:
                    handled = True
            else: break
        if isinstance(result, Exception):
            if self.__parent:
                self.__parent.error("Error reporting [%s]" % message, exception, stackOffset+1, explicitFrame)
            else:
                logging.error("Unhandled error %s" % result)
        elif (self.__propagate or not handled) and self.__parent:
            self.__parent.report(level, message, exception, stackOffset+1, explicitFrame)

    def warning(self, message, exception=None, stackOffset=0, explicitFrame=None):
        self.report(ErrorLevel.LEVEL_WARNING, message, exception, stackOffset + 1, explicitFrame)
    
    def error(self, message, exception=None, stackOffset=0, explicitFrame=None):
        self.report(ErrorLevel.LEVEL_REGULAR, message, exception, stackOffset + 1, explicitFrame)
    
    def fatal(self, message, exception=None, stackOffset=0, explicitFrame=None):
        self.report(ErrorLevel.LEVEL_FATAL, message, exception, stackOffset + 1, explicitFrame)
        
    def setHandler(self, level, handler):
        self.__handlers[level] = handler
        if level not in self.__reportingLevels:
            self.__reportingLevels.append(level)
            self.__reportingLevels.sort()
            
    def removeHandler(self, level):
        if level in self.__handlers:
            del self.__handlers[level]
            self.__reportingLevels.remove(level)
            return True
        return False
    
    def clearHandlers(self):
        self.__handlers = {}
        self.__reportingLevels = []
    
    def getErrorReporter(self, name):
        if not name:
            raise InvalidReporterName()
        splitter = name.find(".")
        if splitter < 0:
            childName = name
            remainder = ""
        elif splitter == 0:
            raise InvalidReporterName()
        else:
            childName = name[:splitter]
            remainder = name[(splitter+1):]
            if not remainder:
                raise InvalidReporterName()
        if childName not in self.__children:
            self.__children[childName] = ErrorReporter(childName, self)
            
        if not remainder:
            return self.__children[childName]
        else:
            return self.__children[childName].getErrorReporter(remainder)


g_ROOT_ERROR_HANDLER = ErrorReporter("")


def GetErrorReporter(name): 
    return name == "" and g_ROOT_ERROR_HANDLER or g_ROOT_ERROR_HANDLER.getErrorReporter(name)
    

class ErrorHandler(object):
    """
    Interface class for all error handling mechanisms. 
    """

    def __init__(self, handlerName=None):
        self.__name = handlerName and handlerName or "<Unnamed %s Handler>" % str(self)
        
    def name(self):
        return self.__name
    
    def handle(self, reporterName, errorLevel, errorMessage, exception=None, stackFrame=None):
        pass


class LoggingErrorHandler(ErrorHandler):
    """
    The LoggingErrorHandler is the default error handler for PLAYGROUND.
    When an error is logged (either as a message or an exception), it is 
    simply logged using the global python logger.
    """

    def __init__(self):
        ErrorHandler.__init__(self, handlerName="Default Logging Error Handler")
        
    def handle(self, reporterName, errorLevel, errorMessage, exception=None, stackFrame=None):
        errMsg = "[ERROR(%s) " % errorLevel
        
        if stackFrame:
            info = inspect.getframeinfo(stackFrame)
            if stackFrame.f_locals.has_key("self"):
                function = "%s.%s" % (stackFrame.f_locals["self"].__class__, info.function)
            else:
                function = info.function
            errMsg += "%s::%d -> " % (function, info.lineno)
        else:
            errMsg += "reported by "
        errMsg += "%s/%s ]\n[DETAILS]\n" % (reporterName and reporterName or "ROOT", self.name())
        errMsg += errorMessage
        
        if exception:
            errMsg += "\n\tAssociated Exception %s" % exception
        if stackFrame:
            errMsg += "\n\tAssociated Trace: %s" % "".join(traceback.format_stack(stackFrame)) 
        
        errMsg = errMsg.decode('ascii', 'replace') + "\n"  
        
        logger = logging.getLogger(reporterName)
        if errorLevel == ErrorLevel.LEVEL_WARNING:
            logger.warning(errMsg)
        elif errorLevel == ErrorLevel.LEVEL_REGULAR or errorLevel < ErrorLevel.LEVEL_FATAL:
            logger.error(errMsg)
        else:
            logger.critical(errMsg)


class SimpleDebugErrorHandler(ErrorHandler):
    """
    This handler is useful in debugging. When used, all exceptions
    above warning are re-raised so that they show up on std out.
    Moreover, all error reports and warnings are also printed
    """
    
    def __init__(self):
        ErrorHandler.__init__(self, handlerName="Simple Debug Error Handler")
        
    def handle(self, reporterName, errorLevel, errorMessage, exception=None, stackFrame=None):
        print("Error reported (%s) by %s: %s" % (errorLevel, reporterName, errorMessage))
        print("Stack trace: %s" % "".join(traceback.format_stack(stackFrame)))
        if exception and errorLevel != ErrorLevel.LEVEL_WARNING:
            print("Re-rasing non-warning exception: ")
            print("\n\n\n", exception, "\n\n\n")
            raise exception


g_ROOT_ERROR_HANDLER.setHandler(ErrorLevel.LEVEL_WARNING, LoggingErrorHandler())
