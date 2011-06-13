//
//  RUBCertKeyTrustDemoAppDelegate.h
//  RUBCertKeyTrustDemo
//
//  Created by Manuel Binna on 01.02.11.
//  Copyright Manuel Binna 2011. All rights reserved.
//

@interface RUBCertKeyTrustDemoAppDelegate : NSObject <UIApplicationDelegate> 
{
    @private
    
    UITabBarController *tabBarController;
    UIWindow *window;
}

@property (nonatomic, retain) IBOutlet UIWindow *window;

@end

