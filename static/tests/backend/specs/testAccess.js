var request = require('ep_etherpad-lite/node_modules/request');

describe('Automated Backend test!', function() {
  var padID;

  beforeEach(function(done) {
//    createPad(function(err, newPadID) {
//      padID = newPadID;
//      done(err);
//    });
    done();
  });

  it('Is a test template that should pass', function(done) {
     if(true !== true) throw new Error("True is not true");
     done();
  });
});
