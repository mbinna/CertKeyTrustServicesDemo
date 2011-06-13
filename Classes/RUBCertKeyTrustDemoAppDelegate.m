//
//  RUBCertKeyTrustDemoAppDelegate.m
//  RUBCertKeyTrustDemo
//
//  Created by Manuel Binna on 01.02.11.
//  Copyright Manuel Binna 2011. All rights reserved.
//

#import "RUBCertKeyTrustDemoAppDelegate.h"
#import "RUBCertViewController.h"
#import "RUBKeyViewController.h"


#pragma mark -

@interface RUBCertKeyTrustDemoAppDelegate ()

@property (nonatomic, retain) UITabBarController *tabBarController;

- (void)setupTabBar;

@end



#pragma mark -

@implementation RUBCertKeyTrustDemoAppDelegate

#pragma mark Properties

@synthesize tabBarController;
@synthesize window;

#pragma mark NSObject

- (void)dealloc 
{
    [tabBarController release];
    [window release];
    
    [super dealloc];
}

#pragma mark UIApplicationDelegate

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions 
{
    [self setupTabBar];
    [[self window] makeKeyAndVisible];

    return YES;
}

#pragma mark RUBCertKeyTrustDemoAppDelegate

- (void)setupTabBar
{
    // First tab
    RUBCertViewController *certVC = [[RUBCertViewController alloc] initWithNibName:nil bundle:nil];
    UINavigationController *certTabNavigationController = [[UINavigationController alloc] 
                                                           initWithRootViewController:certVC];
    UITabBarItem *certTabBarItem = [[UITabBarItem alloc] initWithTitle:@"Certificate" image:nil tag:0];
    [certTabNavigationController setTabBarItem:certTabBarItem];
    [certTabBarItem release];
    [certVC release];
    
    // Second tab
    RUBKeyViewController *keyVC = [[RUBKeyViewController alloc] initWithNibName:nil bundle:nil];
    UINavigationController *keyTabNavigationController = [[UINavigationController alloc] 
                                                          initWithRootViewController:keyVC];
    UITabBarItem *keyTabBarItem = [[UITabBarItem alloc] initWithTitle:@"Key" image:nil tag:1];
    [keyTabNavigationController setTabBarItem:keyTabBarItem];
    [keyTabBarItem release];
    [keyVC release];
    
    // Add tabs to tab bar
    NSArray *tabBarRootViewControllers = [NSArray arrayWithObjects:
                                          certTabNavigationController, 
                                          keyTabNavigationController, 
                                          nil];
    [certTabNavigationController release];
    [keyTabNavigationController release];
    
    UITabBarController *theTabBarController = [[UITabBarController alloc] init];
    [theTabBarController setViewControllers:tabBarRootViewControllers];
    [[self window] addSubview:[theTabBarController view]];
    [self setTabBarController:theTabBarController];
    [theTabBarController release];
}

@end
