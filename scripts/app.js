/*
 Stormpath ID Site v0.3.0
 (c) 2014-2016 Stormpath, Inc. http://stormpath.com
 License: Apache 2.0
*/
'use strict';
(function () {
  angular.module('stormpathIdpApp', ['ngRoute']).config([
    '$routeProvider',
    function ($routeProvider) {
      $routeProvider.when('/', {
        templateUrl: 'views/login.html',
        controller: 'LoginCtrl'
      }).when('/register', {
        templateUrl: 'views/registration.html',
        controller: 'RegistrationCtrl'
      }).when('/forgot/:retry?', {
        templateUrl: 'views/forgot.html',
        controller: 'ForgotCtrl'
      }).when('/reset', {
        templateUrl: 'views/reset.html',
        controller: 'ResetCtrl'
      }).when('/verify', {
        templateUrl: 'views/verify.html',
        controller: 'VerifyCtrl'
      }).when('/unverified', {
        templateUrl: 'views/unverified.html',
        controller: 'UnverifiedCtrl'
      }).otherwise({ redirectTo: '/' });
    }
  ]);
}(window));
'use strict';
angular.module('stormpathIdpApp').controller('LoginCtrl', [
  '$scope',
  'Stormpath',
  '$window',
  function ($scope, Stormpath, $window) {
    $scope.ready = false;
    $scope.canRegister = true;
    $scope.errors = {
      badLogin: false,
      notFound: false,
      userMessage: false,
      unknown: false,
      organizationNameKeyRequired: false,
      organizationNameKeyInvalid: false
    };
    Stormpath.init.then(function initSuccess() {
      $scope.organizationNameKey = Stormpath.getOrganizationNameKey();
      $scope.showOrganizationField = Stormpath.client.jwtPayload.sof;
      $scope.disableOrganizationField = $scope.organizationNameKey !== '';
      $scope.canRegister = !!Stormpath.idSiteModel.passwordPolicy;
      $scope.providers = Stormpath.providers;
      $scope.ready = true;
      $scope.hasProviders = $scope.providers.length > 0;
      if (Stormpath.getProvider('facebook')) {
        initFB();
      }
    });
    var googleIsSignedIn = false;
    function initFB() {
      $window.fbAsyncInit = function () {
        var FB = $window.FB;
        FB.init({
          appId: Stormpath.getProvider('facebook').clientId,
          xfbml: true,
          status: true,
          version: 'v2.0'
        });
      };
      (function (d, s, id) {
        var js, fjs = d.getElementsByTagName(s)[0];
        if (d.getElementById(id)) {
          return;
        }
        js = d.createElement(s);
        js.id = id;
        js.src = '//connect.facebook.net/es_LA/sdk.js';
        fjs.parentNode.insertBefore(js, fjs);
      }($window.document, 'script', 'facebook-jssdk'));
    }
    function clearErrors() {
      Object.keys($scope.errors).map(function (k) {
        $scope.errors[k] = false;
      });
    }
    function showError(err) {
      if (err.status === 400) {
        if (err.code && err.code === 2014) {
          $scope.errors.organizationNameKeyInvalid = true;
        } else {
          $scope.errors.badLogin = true;
        }
      } else if (err.status === 404) {
        $scope.errors.notFound = true;
      } else if (err.userMessage || err.message) {
        $scope.errors.userMessage = err.userMessage || err.message;
      } else {
        $scope.errors.unknown = true;
      }
    }
    function errHandler(err) {
      $scope.submitting = false;
      if (err) {
        showError(err);
      }
    }
    $scope.submit = function () {
      clearErrors();
      if ($scope.showOrganizationField && !$scope.organizationNameKey) {
        $scope.errors.organizationNameKeyRequired = true;
      } else if ($scope.username && $scope.password) {
        $scope.submitting = true;
        var data = {
            login: $scope.username.trim(),
            password: $scope.password.trim()
          };
        if ($scope.organizationNameKey) {
          data.accountStore = { nameKey: $scope.organizationNameKey };
        }
        if (Stormpath.client.jwtPayload.ash) {
          data.accountStore = { href: Stormpath.client.jwtPayload.ash };
        }
        Stormpath.login(data, errHandler);
      } else {
        $scope.errors.emailPasswordRequired = true;
      }
    };
    $scope.googleLogin = function () {
      var gapi = $window.gapi;
      if (!gapi) {
        return;
      }
      clearErrors();
      var params = {
          clientid: Stormpath.getProvider('google').clientId,
          scope: 'email',
          cookiepolicy: 'single_host_origin',
          callback: function (authResult) {
            if (!googleIsSignedIn && authResult.status.signed_in && authResult.status.method === 'PROMPT') {
              googleIsSignedIn = true;
              Stormpath.register({
                providerData: {
                  providerId: 'google',
                  accessToken: authResult.access_token
                }
              }, errHandler);
            }
          }
        };
      gapi.auth.signIn(params);
    };
    function fbRegister(response) {
      Stormpath.register({
        providerData: {
          providerId: 'facebook',
          accessToken: response.authResponse.accessToken
        }
      }, errHandler);
    }
    $scope.facebookLogin = function () {
      var FB = $window.FB;
      FB.login(function (response) {
        if (response.status === 'connected') {
          fbRegister(response);
        }
      }, { scope: 'email' });
    };
    $scope.samlLogin = function (provider) {
      Stormpath.samlLogin(provider.accountStore, errHandler);
    };
    $scope.providerLogin = function (provider) {
      var providerId = provider.providerId;
      var fn = $scope[providerId + 'Login'];
      if (typeof fn !== 'function') {
        console.error('provider login function \'' + providerId + '\' is not implemented');
      } else {
        fn(provider);
      }
    };
    return $scope;
  }
]);
'use strict';
angular.module('stormpathIdpApp').controller('RegistrationCtrl', [
  '$scope',
  function ($scope) {
    return $scope;
  }
]);
'use strict';
angular.module('stormpathIdpApp').controller('ForgotCtrl', [
  '$scope',
  'Stormpath',
  '$routeParams',
  '$rootScope',
  function ($scope, Stormpath, $routeParams, $rootScope) {
    $scope.sent = false;
    $scope.ready = false;
    $scope.retry = $routeParams.retry || false;
    $scope.fields = {};
    $rootScope.$on('$locationChangeStart', function (e) {
      if ($scope.sent) {
        e.preventDefault();
      }
    });
    Stormpath.init.then(function initSuccess() {
      $scope.organizationNameKey = Stormpath.getOrganizationNameKey();
      $scope.showOrganizationField = Stormpath.client.jwtPayload.sof;
      $scope.disableOrganizationField = $scope.organizationNameKey !== '';
      $scope.ready = true;
    });
    $scope.submit = function () {
      $scope.notFound = false;
      var inError = Object.keys($scope.fields).filter(function (f) {
          return $scope.fields[f].validate();
        });
      if (inError.length > 0) {
        return;
      }
      var data = { email: $scope.fields.email.value.trim() };
      if ($scope.organizationNameKey) {
        data.accountStore = { nameKey: $scope.organizationNameKey };
      }
      if (Stormpath.client.jwtPayload.ash) {
        data.accountStore = { href: Stormpath.client.jwtPayload.ash };
      }
      $scope.submitting = true;
      Stormpath.sendPasswordResetEmail(data, function () {
        $scope.sent = true;
        $scope.submitting = false;
      });
    };
  }
]);
'use strict';
angular.module('stormpathIdpApp').controller('ResetCtrl', [
  '$scope',
  'Stormpath',
  '$location',
  function ($scope, Stormpath, $location) {
    $scope.status = 'loading';
    $scope.fields = {};
    var verification;
    Stormpath.init.then(function initSuccess() {
      Stormpath.verifyPasswordToken(function (err, pwTokenVerification) {
        if (err) {
          if (err.status === 404) {
            $location.path('/forgot/retry');
          } else {
            $scope.status = 'failed';
            $scope.error = err.userMessage || err;
          }
        } else {
          $scope.status = 'verified';
          verification = pwTokenVerification;
        }
      });
    });
    $scope.submit = function () {
      var errorCount = Object.keys($scope.fields).filter(function (f) {
          var field = $scope.fields[f];
          return field.validate();
        }).length;
      if (errorCount > 0) {
        return;
      }
      var newPassword = $scope.fields.password.value;
      $scope.submitting = true;
      Stormpath.setNewPassword(verification, newPassword, function (err) {
        $scope.submitting = false;
        if (err) {
          $scope.unknownError = String(err.userMessage || err.developerMessage || err);
        } else {
          $scope.status = 'success';
        }
      });
    };
  }
]);
'use strict';
angular.module('stormpathIdpApp').controller('VerifyCtrl', [
  '$scope',
  'Stormpath',
  function ($scope, Stormpath) {
    $scope.status = 'loading';
    Stormpath.init.then(function initSuccess() {
      Stormpath.verifyEmailToken(function (err) {
        if (err) {
          $scope.status = 'failed';
          $scope.error = String(err.userMessage || err.developerMessage || err.message || err);
        } else {
          $scope.status = 'verified';
        }
      });
    });
  }
]);
'use strict';
angular.module('stormpathIdpApp').controller('ErrorCtrl', [
  '$scope',
  'Stormpath',
  function ($scope, Stormpath) {
    $scope.errors = Stormpath.errors;
    $scope.inError = false;
    $scope.$watchCollection('errors', function () {
      $scope.inError = $scope.errors.length > 0;
    });
  }
]);
'use strict';
angular.module('stormpathIdpApp').service('Stormpath', [
  '$window',
  '$routeParams',
  '$location',
  '$rootScope',
  '$q',
  function Stormpath($window, $routeParams, $location, $rootScope, $q) {
    var self = this;
    var init = $q.defer();
    var params = $location.search();
    var stormpath = $window.Stormpath;
    var ieMatch = $window.navigator.userAgent.match(/MSIE ([0-9.]+)/);
    var client = self.client = null;
    self.init = init.promise;
    self.errors = [];
    self.jwt = params.jwt;
    self.isRegistered = null;
    self.providers = [];
    self.registeredAccount = null;
    self.isVerified = null;
    function showError(error) {
      var msg = error.userMessage || error.developerMessage || error.message || 'Unknown';
      if (self.errors.indexOf(msg) === -1) {
        self.errors.push(msg);
      }
    }
    function ssoEndpointRedirect(serviceProviderCallbackUrl) {
      $window.location = client.baseurl + 'sso/?jwtResponse=' + serviceProviderCallbackUrl.split('jwtResponse=')[1];
    }
    function serviceProviderRedirect(serviceProviderCallbackUrl) {
      $window.location = serviceProviderCallbackUrl;
    }
    function initialize() {
      if (ieMatch && ieMatch[1]) {
        if (parseInt(ieMatch[1], 10) < 10) {
          showError(new Error('Internet Explorer ' + ieMatch[1] + ' is not supported.  Please try again with a newer browser.'));
          return;
        }
      }
      client = self.client = new stormpath.Client(function (err, idSiteModel) {
        $rootScope.$apply(function () {
          if (err) {
            showError(err);
            init.reject(err);
          } else {
            var m = idSiteModel;
            self.idSiteModel = m;
            self.providers = self.providers.concat(m.providers);
            if (m.logoUrl.indexOf('placeholder.placeholder') >= 0) {
              m.logoUrl = m.logoUrl.replace('placeholder.placeholder', self.getSite());
            }
            $rootScope.logoUrl = m.logoUrl;
            init.resolve();
          }
        });
      });
    }
    this.samlLogin = function samlLogin(accountStore, cb) {
      var xhrRequest = {
          method: 'GET',
          url: self.client.appHref + '/saml/sso/idpRedirect?accountStore.href=' + accountStore.href
        };
      self.client.requestExecutor.execute(xhrRequest, function (err, response) {
        if (err) {
          if (err.serviceProviderCallbackUrl) {
            serviceProviderRedirect(err.serviceProviderCallbackUrl);
          } else {
            cb(err);
          }
        } else {
          $window.location = response.serviceProviderCallbackUrl;
        }
      });
    };
    this.login = function login(data, cb) {
      client.login(data, function (err, response) {
        $rootScope.$apply(function () {
          if (err) {
            if (err.serviceProviderCallbackUrl) {
              serviceProviderRedirect(err.serviceProviderCallbackUrl);
            } else {
              cb(err);
            }
          } else {
            ssoEndpointRedirect(response.serviceProviderCallbackUrl);
          }
        });
      });
    };
    this.register = function register(data, cb) {
      client.register(data, function (err, response) {
        $rootScope.$apply(function () {
          if (err) {
            if (err.serviceProviderCallbackUrl) {
              serviceProviderRedirect(err.serviceProviderCallbackUrl);
            } else {
              cb(err);
            }
          } else if (response && response.serviceProviderCallbackUrl) {
            ssoEndpointRedirect(response.serviceProviderCallbackUrl);
          } else {
            self.isRegistered = true;
            $location.path('/unverified');
          }
        });
      });
    };
    this.verifyEmailToken = function verifyEmailToken(cb) {
      client.verifyEmailToken(function (err) {
        $rootScope.$apply(function () {
          self.isVerified = err ? false : true;
          cb(err);
        });
      });
    };
    this.verifyPasswordToken = function verifyPasswordToken(cb) {
      client.verifyPasswordResetToken(function (err, resp) {
        $rootScope.$apply(function () {
          cb(err, resp);
        });
      });
    };
    this.sendPasswordResetEmail = function sendPasswordResetEmail(email, cb) {
      client.sendPasswordResetEmail(email, function (err) {
        $rootScope.$apply(function () {
          if (err) {
            if (err.serviceProviderCallbackUrl) {
              serviceProviderRedirect(err.serviceProviderCallbackUrl);
            } else {
              cb(err);
            }
          } else {
            cb();
          }
        });
      });
    };
    this.setNewPassword = function setNewPassword(pwTokenVerification, newPassword, cb) {
      client.setAccountPassword(pwTokenVerification, newPassword, function (err, resp) {
        $rootScope.$apply(function () {
          cb(err, resp);
        });
      });
    };
    this.getOrganizationNameKey = function getOrganizationNameKey() {
      return client.jwtPayload.asnk || '';
    };
    this.getSite = function getSite() {
      var parser = document.createElement('a');
      parser.href = document.referrer;
      // only works for .com
      return parser.hostname.replace('.com', '').split('.').pop() + '.com';
    };
    this.getProvider = function getProvider(providerId) {
      var r = self.providers.filter(function (p) {
          return p.providerId === providerId;
        });
      return r.length === 1 ? r[0] : null;
    };
    initialize();
    return this;
  }
]);
'use strict';
angular.module('stormpathIdpApp').controller('RegistrationFormCtrl', [
  '$scope',
  'Stormpath',
  function ($scope, Stormpath) {
    $scope.fields = {};
    $scope.submit = function () {
      $scope.unknownError = false;
      var inError = Object.keys($scope.fields).filter(function (f) {
          var field = $scope.fields[f];
          return field.validate();
        });
      var data = Object.keys($scope.fields).reduce(function (acc, f) {
          acc[f] = $scope.fields[f].value;
          return acc;
        }, {});
      delete data.passwordConfirm;
      if (inError.length === 0) {
        $scope.submitting = true;
        Stormpath.register(data, function (err) {
          $scope.submitting = false;
          if (err) {
            if (err.status === 409) {
              $scope.fields.email.setError('duplicateUser', true);
            } else {
              $scope.unknownError = String(err.userMessage || err.developerMessage || err);
            }
          }
        });
      }
    };
  }
]);
'use strict';
angular.module('stormpathIdpApp').directive('formGroup', function () {
  return {
    restrict: 'A',
    scope: true,
    link: function postLink(scope, element, attrs) {
      scope.validationError = false;
      scope.errors = {};
      scope.$watch('validationError', function () {
        element.toggleClass(attrs.errorClass || 'has-error', scope.validationError);
      });
      scope.$watchCollection('errors', function () {
        var errorCount = Object.keys(scope.errors).filter(function (k) {
            return scope.errors[k];
          }).length;
        element.toggleClass(attrs.errorClass || 'has-error', scope.validationError || errorCount > 0);
      });
    }
  };
});
'use strict';
angular.module('stormpathIdpApp').directive('formControl', function () {
  return {
    restrict: 'A',
    link: function postLink(scope, element, attrs) {
      var fieldname = attrs.name;
      if (!scope.fields) {
        scope.fields = {};
      }
      scope.fields[fieldname] = {
        value: element.val(),
        validationError: false,
        errors: scope.errors || {},
        setError: function (k, v) {
          if (typeof scope.setError === 'function') {
            scope.setError(k, v);
          }
        },
        validate: function () {
          return typeof scope.validate === 'function' ? scope.validate(element) : true;
        }
      };
      scope.clearErrors = function () {
        Object.keys(scope.errors).map(function (k) {
          scope.errors[k] = false;
        });
      };
      element.on('input', function () {
        scope.$apply(function (scope) {
          scope.fields[fieldname].value = element.val();
        });
      });
      scope.$watchCollection('errors', function (a) {
        angular.extend(scope.fields[fieldname].errors, a || {});
      });
      scope.$watchCollection('fields.' + fieldname + '.errors', function (a) {
        angular.extend(scope.errors, a || {});
      });
    }
  };
});
'use strict';
angular.module('stormpathIdpApp').directive('validateOnBlur', function () {
  return {
    restrict: 'A',
    link: function postLink(scope, element) {
      element.on('blur', function () {
        scope.$apply(function () {
          scope.validate(element);
        });
      });
    }
  };
});
'use strict';
angular.module('stormpathIdpApp').directive('nameValidation', function () {
  return {
    restrict: 'A',
    link: function postLink(scope) {
      scope.validate = function (element) {
        scope.clearErrors();
        var t = element.val() === '';
        scope.validationError = t;
        return t;
      };
    }
  };
});
'use strict';
angular.module('stormpathIdpApp').directive('emailValidation', function () {
  var re = /^(([^<>()[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)|(\".+\"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
  return {
    restrict: 'A',
    link: function postLink(scope) {
      scope.errors = { duplicateUser: false };
      scope.setError = function (k, v) {
        scope.errors[k] = v;
      };
      scope.validate = function (element) {
        scope.clearErrors();
        var val = element.val().trim();
        var t = val === '' ? true : !re.test(val);
        scope.validationError = t;
        return t;
      };
    }
  };
});
'use strict';
angular.module('stormpathIdpApp').directive('passwordMatchValidation', function () {
  return {
    restrict: 'A',
    link: function postLink(scope) {
      scope.validate = function (element) {
        var t = scope.fields.password.value !== '' && element.val() !== scope.fields.password.value;
        scope.validationError = t;
        return t;
      };
    }
  };
});
'use strict';
angular.module('stormpathIdpApp').directive('passwordPolicyValidation', [
  'Stormpath',
  function (Stormpath) {
    return {
      restrict: 'A',
      link: function postLink(scope) {
        scope.errors = {
          minLength: false,
          maxLength: false,
          requireLowerCase: false,
          requireUpperCase: false,
          requireNumeric: false,
          requireDiacritical: false
        };
        scope.errorCount = function () {
          return Object.keys(scope.errors).filter(function (k) {
            return scope.errors[k];
          }).length;
        };
        scope.validate = function (element) {
          scope.clearErrors();
          var v = element.val();
          var tests = [
              [
                'minLength',
                function () {
                  return v.length < Stormpath.idSiteModel.passwordPolicy.minLength;
                }
              ],
              [
                'maxLength',
                function () {
                  return v.length > Stormpath.idSiteModel.passwordPolicy.maxLength;
                }
              ],
              [
                'requireLowerCase',
                function () {
                  return Stormpath.idSiteModel.passwordPolicy.requireLowerCase && !/[a-z]/.test(v);
                }
              ],
              [
                'requireUpperCase',
                function () {
                  return Stormpath.idSiteModel.passwordPolicy.requireUpperCase && !/[A-Z]/.test(v);
                }
              ],
              [
                'requireNumeric',
                function () {
                  return Stormpath.idSiteModel.passwordPolicy.requireNumeric && !/[0-9]/.test(v);
                }
              ],
              [
                'requireDiacritical',
                function () {
                  return Stormpath.idSiteModel.passwordPolicy.requireDiacritical && !/[\u00C0-\u017F]/.test(v);
                }
              ]
            ];
          for (var i = 0; i < tests.length; i++) {
            scope.errors[tests[i][0]] = tests[i][1](v);
            if (scope.errorCount() > 0) {
              break;
            }
          }
          scope.validationError = scope.errorCount() > 0;
          return scope.validationError;
        };
      }
    };
  }
]);
'use strict';
angular.module('stormpathIdpApp').controller('UnverifiedCtrl', [
  '$scope',
  'Stormpath',
  '$location',
  function ($scope, Stormpath, $location) {
    if (!Stormpath.isRegistered) {
      $location.path('/');
    }
  }
]);