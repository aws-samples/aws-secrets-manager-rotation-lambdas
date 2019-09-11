var AWS = require('aws-sdk');
var codebuild = new AWS.CodeBuild();
exports.handler = async function(event, context, callback) {
    try {
        console.log('REQUEST RECEIVED:\n' + JSON.stringify(event));
        if (event.RequestType === 'Create') {
            console.log('CREATE!');
            var params = {
                projectName: event.ResourceProperties.BuildProjectName
            };
            var buildResp = await codebuild.startBuild(params).promise();
            console.log(JSON.stringify(buildResp));
            console.log("Waiting..");
            await wait(120 * 1000);
            console.log("Done waiting.");
            await sendResponse(event, context, 'SUCCESS', { 'Message': 'Resource creation successful!' });
        } else if (event.RequestType === 'Update') {
            console.log('UDPATE!');
            await sendResponse(event, context, 'SUCCESS', { 'Message': 'Resource update successful!' });
        } else if (event.RequestType === 'Delete') {
            console.log('DELETE!');
            await sendResponse(event, context, 'SUCCESS', { 'Message': 'Resource deletion successful!' });
        } else {
            console.log('FAILED!');
            await sendResponse(event, context, 'FAILED');
        }
    } catch (error) {
        console.log('ERROR!');
        console.log(error);
        await sendResponse(event, context, 'FAILED', error);
    }
};
async function sendResponse(e, ctx, rs, rd) {
    return new Promise(function (resolve) {
        var body = JSON.stringify({
            Status: rs,
            Reason: 'See the details in CloudWatch Log Stream: ' + ctx.logStreamName,
            PhysicalResourceId: ctx.logStreamName,
            StackId: e.StackId,
            RequestId: e.RequestId,
            LogicalResourceId: e.LogicalResourceId,
            NoEcho: false,
            Data: rd
        });
        var h = require("https");
        var u = require("url");
        var p = u.parse(e.ResponseURL);
        var req = h.request({
            hostname: p.hostname,
            port: 443,
            path: p.path,
            method: "PUT",
            headers: {
                'content-type': '',
                'content-length': body.length
            }
        }, resp => { resolve(); });
        req.write(body);
        req.end();
    });
}
function wait(timeout) {
    return new Promise((resolve) => {
        setTimeout(() => {
            resolve();
        }, timeout);
    });
}