#include <string>
#include <iostream>
#include <fstream>

#include <ovpncli/ovpncli.hpp>

#import "ovpncli.h"

using namespace openvpn;

@interface OVPNConfig ()
- (void) toClientAPI:(ClientAPI::Config *)dest;
@end

@interface OVPNServerEntry ()
+ (OVPNServerEntry *) fromClientAPI:(const ClientAPI::ServerEntry *)src;
@end

@interface OVPNEvalConfig ()
+ (OVPNEvalConfig *) fromClientAPI:(const ClientAPI::EvalConfig *)src;
@end

@interface OVPNProvideCreds ()
- (void) toClientAPI:(ClientAPI::ProvideCreds *)dest;
@end

@interface OVPNDynamicChallenge ()
+ (OVPNDynamicChallenge *) fromClientAPI:(BOOL)return_status dyn_chal:(const ClientAPI::DynamicChallenge *)src;
@end

@interface OVPNEvent ()
+ (OVPNEvent *) fromClientAPI:(const ClientAPI::Event *)src;
@end

@interface OVPNLogInfo ()
+ (OVPNLogInfo *) fromClientAPI:(const ClientAPI::LogInfo *)src;
@end

@interface OVPNStatus ()
+ (OVPNStatus *) fromClientAPI:(const ClientAPI::Status *)src;
@end

class OpenVPNClientWrapper : public ClientAPI::OpenVPNClient
{
public:
  OpenVPNClientWrapper(__unsafe_unretained OVPNClientBase *parent_arg)
    : parent(parent_arg)
  {
  }

private:
  virtual bool socket_protect(int socket)
  {
    return [parent socket_protect:socket];
  }

  virtual void event(const ClientAPI::Event& ev)
  {
    OVPNEvent *e = [OVPNEvent fromClientAPI:&ev];
    [parent event:e];
  }

  virtual void log(const ClientAPI::LogInfo& log)
  {
    OVPNLogInfo *li = [OVPNLogInfo fromClientAPI:&log];
    [parent log:li];
  }

  virtual void external_pki_cert_request(ClientAPI::ExternalPKICertRequest& certreq)
  {
    certreq.error = true;
    certreq.errorText = "external_pki_cert_request not implemented";
  }

  virtual void external_pki_sign_request(ClientAPI::ExternalPKISignRequest& signreq)
  {
    signreq.error = true;
    signreq.errorText = "external_pki_sign_request not implemented";
  }

  __unsafe_unretained OVPNClientBase *parent;
};

@implementation OVPNConfig

@synthesize content;
@synthesize serverOverride;
@synthesize protoOverride;
@synthesize connTimeout;
@synthesize externalPkiAlias;

- (void) toClientAPI:(ClientAPI::Config *)dest
{
  if (content)
    dest->content = [ content UTF8String ];
  if (serverOverride)
    dest->serverOverride = [ serverOverride UTF8String ];
  if (protoOverride)
    dest->protoOverride = [ protoOverride UTF8String ];
  dest->connTimeout = connTimeout;
  if (externalPkiAlias)
    dest->externalPkiAlias = [ externalPkiAlias UTF8String ];
}

- (NSString *) description
{
  return [NSString stringWithFormat:@"Config clen=%lu so=%@ po=%@ to=%d epkia=%@", [content length], serverOverride, protoOverride, connTimeout, externalPkiAlias];
}

@end

@implementation OVPNServerEntry

@synthesize server;
@synthesize friendlyName;

+ (OVPNServerEntry *) fromClientAPI:(const ClientAPI::ServerEntry *)src
{
  OVPNServerEntry *dest = [[OVPNServerEntry alloc] init];
  dest->server = [NSString stringWithUTF8String:src->server.c_str()];
  dest->friendlyName = [NSString stringWithUTF8String:src->friendlyName.c_str()];
  return dest;
}

- (NSString *) description
{
  return [NSString stringWithFormat:@"%@/%@", server, friendlyName];
}

@end

@implementation OVPNEvalConfig

@synthesize error;
@synthesize message;
@synthesize userlockedUsername;
@synthesize profileName;
@synthesize friendlyName;
@synthesize autologin;
@synthesize externalPki;
@synthesize staticChallenge;
@synthesize staticChallengeEcho;
@synthesize serverList;

+ (OVPNEvalConfig *) fromClientAPI:(const ClientAPI::EvalConfig *)src
{
  OVPNEvalConfig *dest = [[OVPNEvalConfig alloc] init];
  dest->error = (BOOL)src->error;
  dest->message = [NSString stringWithUTF8String:src->message.c_str()];
  dest->userlockedUsername = [NSString stringWithUTF8String:src->userlockedUsername.c_str()];
  dest->profileName = [NSString stringWithUTF8String:src->profileName.c_str()];
  dest->friendlyName = [NSString stringWithUTF8String:src->friendlyName.c_str()];
  dest->autologin = (BOOL)src->autologin;
  dest->externalPki = (BOOL)src->externalPki;
  dest->staticChallenge = [NSString stringWithUTF8String:src->staticChallenge.c_str()];
  dest->staticChallengeEcho = (BOOL)src->staticChallengeEcho;

  {
    const NSUInteger size = src->serverList.size();
    NSMutableArray* sl = [NSMutableArray arrayWithCapacity:size];
    for (NSUInteger i = 0; i < size; ++i)
      {
	OVPNServerEntry *se = [OVPNServerEntry fromClientAPI:&src->serverList[i]];
	[ sl addObject:se ];
      }
    dest->serverList = sl;
  }

  return dest;
}

- (NSString *) description
{
  return [NSString stringWithFormat:@"EvalConfig err=%d msg=%@ user=%@ prof=%@ f=%@ auto=%d epki=%d sc=%@ sce=%d serv=%@", error, message, userlockedUsername, profileName, friendlyName, autologin, externalPki, staticChallenge, staticChallengeEcho, [serverList componentsJoinedByString: @","]];
}

@end

@implementation OVPNProvideCreds

@synthesize username;
@synthesize password;
@synthesize response;
@synthesize dynamicChallengeCookie;
@synthesize replacePasswordWithSessionID;

- (void) toClientAPI:(ClientAPI::ProvideCreds *)dest
{
  if (username)
    dest->username = [ username UTF8String ];
  if (password)
    dest->password = [ password UTF8String ];
  if (response)
    dest->response = [ response UTF8String ];
  if (dynamicChallengeCookie)
    dest->dynamicChallengeCookie = [ dynamicChallengeCookie UTF8String ];
  dest->replacePasswordWithSessionID = replacePasswordWithSessionID;
}

@end

@implementation OVPNDynamicChallenge

@synthesize status;
@synthesize challenge;
@synthesize echo;
@synthesize responseRequired;

+ (OVPNDynamicChallenge *) fromClientAPI:(BOOL)return_status dyn_chal:(const ClientAPI::DynamicChallenge *)src;
{
  OVPNDynamicChallenge *dest = [[OVPNDynamicChallenge alloc] init];
  dest->status = (BOOL)return_status;
  dest->challenge = [NSString stringWithUTF8String:src->challenge.c_str()];
  dest->echo = (BOOL)src->echo;
  dest->responseRequired = (BOOL)src->responseRequired;
  return dest;
}

- (NSString *) description
{
  return [NSString stringWithFormat:@"Challenge %@ echo=%d req=%d", challenge, echo, responseRequired];
}

@end

@implementation OVPNEvent

@synthesize error;
@synthesize name;
@synthesize info;

+ (OVPNEvent *) fromClientAPI:(const ClientAPI::Event *)src
{
  OVPNEvent *dest = [[OVPNEvent alloc] init];
  dest->error = (BOOL)src->error;
  dest->name = [NSString stringWithUTF8String:src->name.c_str()];
  dest->info = [NSString stringWithUTF8String:src->info.c_str()];
  return dest;
}

- (NSString *) description
{
  return [NSString stringWithFormat:@"Event %@ %@ err=%d", name, info, error];
}

@end

@implementation OVPNLogInfo

@synthesize text;

+ (OVPNLogInfo *) fromClientAPI:(const ClientAPI::LogInfo *)src
{
  OVPNLogInfo *dest = [[OVPNLogInfo alloc] init];
  dest->text = [NSString stringWithUTF8String:src->text.c_str()];
  return dest;
}

- (NSString *) description
{
  return [NSString stringWithFormat:@"Log %@", text];
}

@end

@implementation OVPNStatus

@synthesize error;
@synthesize message;

+ (OVPNStatus *) fromClientAPI:(const ClientAPI::Status *)src
{
  OVPNStatus *dest = [[OVPNStatus alloc] init];
  dest->error = (BOOL)src->error;
  dest->message = [NSString stringWithUTF8String:src->message.c_str()];
  return dest;
}

- (NSString *) description
{
  return [NSString stringWithFormat:@"Status err=%d %@", error, message];
}

@end

@interface OVPNClientBase () {
  OpenVPNClientWrapper* ovpncli;
}

@end

@implementation OVPNClientBase

- (id)init
{
  self = [super init];
  if (self)
    {
      ovpncli = new OpenVPNClientWrapper((__unsafe_unretained OVPNClientBase *)self);
      if (!ovpncli)
	self = nil;
    }
  return self;
}

- (void)dealloc
{
  //NSLog (@"DELETE ovpncli"); // fixme
  delete ovpncli;
}

+ (OVPNEvalConfig *)eval_config_static:(OVPNConfig *)config
{
  ClientAPI::Config cc;
  [config toClientAPI:&cc];
  ClientAPI::EvalConfig ec = OpenVPNClientWrapper::eval_config_static(cc);
  return [OVPNEvalConfig fromClientAPI:&ec];
}

- (OVPNEvalConfig *)eval_config:(OVPNConfig *)config
{
  ClientAPI::Config cc;
  [config toClientAPI:&cc];
  ClientAPI::EvalConfig ec = ovpncli->eval_config(cc);
  return [OVPNEvalConfig fromClientAPI:&ec];
}

- (OVPNStatus *)provide_creds:(OVPNProvideCreds *)creds
{
  ClientAPI::ProvideCreds pc;
  [creds toClientAPI:&pc];
  ClientAPI::Status s = ovpncli->provide_creds(pc);
  return [OVPNStatus fromClientAPI:&s];
}

+ (OVPNDynamicChallenge *)parse_dynamic_challenge:(NSString *)cookie
{
  const std::string cookie_cpp([cookie UTF8String ]);
  ClientAPI::DynamicChallenge dc_cpp;
  const bool status = OpenVPNClientWrapper::parse_dynamic_challenge(cookie_cpp, dc_cpp);
  return [OVPNDynamicChallenge fromClientAPI:status dyn_chal:&dc_cpp];
}

- (OVPNStatus *)connect
{
  ClientAPI::Status status = ovpncli->connect();
  return [OVPNStatus fromClientAPI:&status];
}

- (void)stop
{
  ovpncli->stop();
}

- (void)pause
{
  ovpncli->pause();
}

- (void)resume
{
  ovpncli->resume();
}

+ (int)stats_n
{
  return OpenVPNClientWrapper::stats_n();
}

+ (NSString *)stats_name:(int)index
{
  const std::string name = OpenVPNClientWrapper::stats_name(index);
  return [NSString stringWithUTF8String:name.c_str()];
}

- (long long)stats_value:(int)index
{
  return ovpncli->stats_value(index);
}

- (NSArray *)stats_bundle // returns array of NSNumber containing long longs
{
  const std::vector<long long> stats = ovpncli->stats_bundle();
  const NSUInteger size = stats.size();
  NSMutableArray* ret = [NSMutableArray arrayWithCapacity:size];
  for (NSUInteger i = 0; i < size; ++i)
    {
      NSNumber *num = [NSNumber numberWithLongLong:stats[i]];
      [ ret addObject:num ];
    }
  return ret;
}

+ (int)app_expire
{
  return OpenVPNClientWrapper::app_expire();
}

+ (NSString *)copyright
{
  const std::string cr = OpenVPNClientWrapper::copyright();
  return [NSString stringWithUTF8String:cr.c_str()];
}

- (void)event:(OVPNEvent *)ev
{
}

- (void)log:(OVPNLogInfo *)li
{
}

- (BOOL)socket_protect:(int)socket
{
  return YES;
}

@end
