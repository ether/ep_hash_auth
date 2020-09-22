var request = require('ep_etherpad-lite/node_modules/request');

describe('Automated Backend test!', function() {

  beforeEach(function(done) {
//    createPad(function(err, newPadID) {
//      padID = newPadID;
//      done(err);
//    });
    done();
  });

  it('Is a test template that should pass', function(done) {
     if(true !== true) throw new Error("true is not true");
     done();
  });
});
