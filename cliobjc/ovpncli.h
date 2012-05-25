// Objective-C wrapping of ovpncli.hpp

#import <Foundation/Foundation.h>

@interface OVPNConfig: NSObject

@property(nonatomic, strong) NSString *content;
@property(nonatomic, strong) NSString *serverOverride;
@property(nonatomic, strong) NSString *protoOverride;
@property int connTimeout;
@property(nonatomic, strong) NSString *externalPkiAlias;

- (NSString *) description;

@end

@interface OVPNServerEntry: NSObject

@property(readonly, nonatomic, strong) NSString *server;
@property(readonly, nonatomic, strong) NSString *friendlyName;

- (NSString *) description;

@end

@interface OVPNEvalConfig: NSObject

@property(readonly) BOOL error;
@property(readonly, nonatomic, strong) NSString *message;
@property(readonly, nonatomic, strong) NSString *userlockedUsername;
@property(readonly, nonatomic, strong) NSString *profileName;
@property(readonly, nonatomic, strong) NSString *friendlyName;
@property(readonly) BOOL autologin;
@property(readonly) BOOL externalPki;
@property(readonly, nonatomic, strong) NSString *staticChallenge;
@property(readonly) BOOL staticChallengeEcho;
@property(readonly, nonatomic, strong) NSArray *serverList; // array of ServerEntry

- (NSString *) description;

@end

@interface OVPNProvideCreds: NSObject

@property(nonatomic, strong) NSString *username;
@property(nonatomic, strong) NSString *password;
@property(nonatomic, strong) NSString *response;
@property(nonatomic, strong) NSString *dynamicChallengeCookie;
@property BOOL replacePasswordWithSessionID;

@end

@interface OVPNDynamicChallenge: NSObject

@property(readonly) BOOL status;
@property(readonly, nonatomic, strong) NSString *challenge;
@property(readonly) BOOL echo;
@property(readonly) BOOL responseRequired;

- (NSString *) description;

@end

@interface OVPNEvent: NSObject

@property(readonly) BOOL error;
@property(readonly, nonatomic, strong) NSString *name;
@property(readonly, nonatomic, strong) NSString *info;

- (NSString *) description;

@end

@interface OVPNLogInfo: NSObject

@property(readonly, nonatomic, strong) NSString *text;

- (NSString *) description;

@end

@interface OVPNStatus: NSObject

@property(readonly) BOOL error;
@property(readonly, nonatomic, strong) NSString *message;

- (NSString *) description;

@end

@interface OVPNClientBase: NSObject

- (id)init;
- (void)dealloc;

+ (OVPNEvalConfig *)eval_config_static:(OVPNConfig *)config;
- (OVPNEvalConfig *)eval_config:(OVPNConfig *)config;

- (OVPNStatus *)provide_creds:(OVPNProvideCreds *)creds;

+ (OVPNDynamicChallenge *)parse_dynamic_challenge:(NSString *)cookie;

- (OVPNStatus *)connect;

- (void)stop;
- (void)pause;
- (void)resume;

+ (int)stats_n;
+ (NSString *)stats_name:(int)index;
- (long long)stats_value:(int)index;
- (NSArray *)stats_bundle; // returns array of NSNumber containing long longs

+ (int)app_expire;
+ (NSString *)copyright;

// methods intended to be overriden

- (void)event:(OVPNEvent *)ev;
- (void)log:(OVPNLogInfo *)li;
- (BOOL)socket_protect:(int)socket;

@end
