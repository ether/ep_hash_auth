var request = require('request');

describe('padCopy hook', function() {
  console.error("HI KIDS");
  var padID;

  beforeEach(function(done) {
    createPad(function(err, newPadID) {
      padID = newPadID;
      done(err);
    });
  });

  it('creates copies of pad comments when pad is duplicated', function(done) {
    // create comment...
    createComment(padID, {}, function(err, comment) {
      if (err) throw err;
      // ... duplicate pad...
      var copiedPadID = padID+'-copy';
      copyPad(padID, copiedPadID, function() {
        // ... and finally check if comments are returned
        var getCommentsRoute = commentsEndPointFor(copiedPadID)+'?apikey='+apiKey;
        api.get(getCommentsRoute)
        .expect(function(res) {
          var commentsFound = Object.keys(res.body.data.comments);
          if(commentsFound.length !== 1) {
            throw new Error('Comments from pad should had been copied.');
          }
        })
        .end(done);
      });
    });
  });
});
