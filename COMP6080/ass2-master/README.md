# Assessment 2 - Vanilla JS: Slackr

1. Background & Motivation
2. The Task
3. Getting Started
4. Constraints & Assumptions
5. Marking Criteria
6. Originality of Work
7. Submission
8. Late Submission Policy

## 0. Change Log

N/A

## 1. Background & Motivation

Web-based applications are becoming the most common way to build a digital capability accessible to a mass audience. While there are modern tools that help us build these rapidly, it's important to understand the fundamental JavaScript-based technology and architectures that exist, both to gain a deeper understanding for when these skills may be needed, but also to simply understand the mechanics of fundamental JS. Even when working with a high level framework like ReactJS, understanding (in-concept) the code that it is transpiled to will ensure you're a more well rounded web-based engineer.

This assignment consists of building a **frontend** website in Vanilla JS (no ReactJS or other frameworks). This frontend will interact with a RESTful API HTTP backend that is built in JavaScript (NodeJS express server) and provided to you.

A theoretical background on how to interface with this API can be found the "promises & fetch" lecture.

The web-based application you build is required to be a single page app (SPA). Single page apps give websites an "app-like feeling", and are characterised by their use of a single full load of an initial HTML page, and then using AJAX/fetch to dynamically manipulate the DOM without ever requiring a full page reload. In this way, SPAs are generated, rendered, and updated using JavaScript. Because SPAs don’t require a user to navigate away from a page to do anything, they retain a degree of user and application state. In short, this means you will only ever have `index.html` as your HTML page, and that any sense of "moving between pages" will just be modifications of the DOM.

## 2. The Task

Your task is to build a frontend for a UNSW rip-off version of the popular messaging tool [Slack](https://slack.com/). If you haven't used this application before (or similar applications like Discord, Teams), we would recommend creating your own slack workspace to place around with the tool.

UNSW's rip-off of slack is called "Slackr". However, you don't have to build the entire application. You only have to build the frontend. The backend is already built for you as an express server built in NodeJS (see section 3.2).

Instead of providing visuals of what the frontend (your task) should look like, we intend are providing you with a number of clear and short requirements about expected features and behaviours.

The requirements describe a series of **screens**. Screens can be popups/modals, or entire pages. The use of that language is so that you can choose how you want it to be displayed. A screen is essentially a certain state of your web-based application.

### 2.1. Milestone 1 - Registration & Login (15%)

This focuses on the basic user interface to register and log in to the site.

#### 2.1.1. Login
 * When the user isn't logged in, the site shall present a login form that contains:
   * an email field (text)
   * a password field (password)
   * submit button to login
 * When the submit button is pressed, the form data should be sent to `POST /auth/login` to verify the credentials. If there is an error during login an appropriate error should appear on the screen.

#### 2.1.2. Registration
 * When the user isn't logged in, the login form shall provide a link/button that opens the register form. The register form will contain:
   * an email field (text)
   * a name field (text)
   * a password field (password)
   * a confirm password field (password) - not passed to the backend, but an error should be thrown on submit if it doesn't match the other password
   * submit button to register
 * When the submit button is pressed, if the two passwords don't match the user should receive an error popup. If they do match, the form data should be sent to `POST /auth/register` to verify the credentials. If there is an error during registration an appropriate error should appear on the screen.

#### 2.1.3. Error Popup
 * Whenever the frontend or backend produces an error, there shall be an error popup on the screen with a message (either a message derived from the backend error response, or one meaningfully created on the frontend).
 * This popup can be closed/removed/deleted by pressing an "x" or "close" button.

### 2.2. Milestone 2 - Creating and viewing channels (10%)

Milestone 2 focuses on creating **channels**, and viewing the basic channel screen layout for a single channel.

#### 2.2.1 Viewing a list of channels
 * The application should present a list of all public channels created. This will be visible on every screen for a logged-in user.
 * The user should also be able to see a list of all private channels they have joined. This will be visible on every screen for a logged-in user.
 * The two types of channels should be distinguishable visually.
 * Selecting a channel should take the user to the single channel screen. This single channel screen should show the channel's messages and other features (implemented in `2.3`).
 * If a user has logged in, but has not selected a channel yet, there are no rules around what the main body of the screen should display (reminder: the list of channels should still be visible somewhere, in some form).

#### 2.2.2 Creating a new channel
 * Users should be able to create a new channel via some kind of form.
 * The trigger to display the form should be accessible on any screen with no more than 2 clicks.
 * Users should be able to enter the name, an optional description, and public/private channel type.
 * Note: the description should be optional for the user but the backend requires a description.

#### 2.2.3 Viewing and editing channel details
 * When viewing a single channel screen, certain information should be accessible/visible within 0-1 clicks.
 * This information includes the name of the channel, description, public/private setting, creation timestamp (as a time/date not as an ISO string, flexible to whatever you think is user-friendly), and name of the creator of the channel.
 * Users should be able to edit the channel's name and description in some way.
 * If the user is not a member of the channel, they do not need to see the channel details, but should be given a way to join the channel.
 * If the user is a member of the channel, there should be an option to leave the channel.

### 2.3. Milestone 3 - Channel messages (18%)

Milestone 3 focuses on the display and interaction of messages on a single channel screen.

#### 2.3.1 Viewing channel messages
 * The channel's messages can be viewed on each single channel screen.
 * Each message should display the sender's name and profile photo, and message timestamp (as a time/date not as an ISO string, flexible to whatever you think is user-friendly).
 * If the user has no profile photo, the frontend should use a default image.
 
#### 2.3.2 Message pagination
 * Users can page between sets of messages in the channel.
 * Note: you can ignore this if you properly implement infinite scroll in milestone 6.

#### 2.3.3 Sending messages
 * Users can send new messages from the single channel screen.
 * Once messages are sent, the channel messages should automatically update without requiring a page reload/refresh.
 * The frontend should validate the message so that empty strings or messages containing only whitespace cannot be sent.

#### 2.3.4 Deleting messages
 * Users can delete their own messages they see displayed from the single channel screen.
 * Once messages are deleted, the channel messages should automatically update without requiring a page reload/refresh.

#### 2.3.5 Editing messages
 * Users can edit their own messages they see displayed from the single channel screen.
 * Once messages are edited, there should be an indication that they have been edited, as well as the timestamp (as a time/date not as an ISO string, flexible to whatever you think is user-friendly).
 * The frontend should validate the message so that a user cannot edit a message to the same existing message.

#### 2.3.6 Reacting to messages
 * Users can react and unreact to messages.
 * You should provide at least 3 different reactions.
 * Reactions must be UTF-8 emojis.

#### 2.3.7 Pinning messages
 * Users can pin and unpin messages.
 * There should be a way for users to view all the channel's pinned messages at once. If the user is only on the first page of messages, but there is a pinned message on the third page, they should not have to navigate to the third page to see it.

### 2.4. Milestone 4 - Multi-user interactivity (10%)

Milestone 4 focuses on the interactions that come from having multiple users in the system.

#### 2.4.1 Inviting users to a channel
 * Users should be able to add other users to a channel from a modal. Users are visually identified by their name.
 * Users should be able to select multiple users to add at the same time.
 * When selecting the user(s), they must be displayed in alphabetical order of their name.

#### 2.4.2 User profiles
 * Within a single channel screen, if you click on a users' name on a given message, it should display their profile screen.
 * Their profile photo, name, bio, and email should be displayed on this screen.

#### 2.4.3 Viewing and editing user's own profile
 * On all logged in screens, there must be a way for the user to view their own profile screen.
 * On a user's own profile screen, they should also be able to see the field for their password.
 * On a user's own profile screen, they should be able to toggle between viewing their password in plain text and hidden as a string of asterisks/dots of the correct length. It is hidden by default.
 * On a user's own profile screen, they can update their own profile, including name, bio, email, and password.
 * On a user's own profile screen, they should be able to upload and change their profile photo.

### 2.5. Milestone 5 - Photos in channels (7%)

Milestone 5 focuses on being able to upload and send photos as part of messages in a single channel screen.

#### 2.5.1 Sending photos in channels
 * Users should be able to upload and send photos in a single channel screen using the `POST /message/{channelId}`.
 * A message that contains an image does not include text as well.

#### 2.5.2 Viewing photos in channels
 * Photos in the channel messages should be displayed as small thumbnails, with the option to click to enlarge the image in a modal.
 * In the modal, there should be arrow buttons allowing the user to view other images sent in the channel.

### 2.6. Milestone 6 - Challenge components (5%)

Milestone 6 focuses on some harder components that are designed to start to separate out HD (High Distinction) students from one another. These features require independent learning and research.

#### 2.6.1 Infinite Scroll
 * Instead of pagination, users can infinitely scroll through messages. For infinite scroll to be properly implemented, you need to progressively load posts as you scroll.
 * Once users have reached the end of a set of messages, while the fetch is happening, they should see a message or icon indicating that the next set of messages are currently being fetched.

#### 2.6.2 Push notifications
 * Users can receive push notifications when another user posts to a channel they have joined.
 * To know whether someone or not has made a post, you must "poll" the server (i.e. intermittent requests, maybe every second, that check the state).
 * Polling is very inefficient for browsers, but can often be used as it simplifies the technical needs on the server.

### 2.7. Milestone 7 - Extra challenge components (5%)

Milestone 7 focuses on some even harder components that are designed to start to separate out HD (High Distinction) students from one another. These features require independent learning and research.

#### 2.7.1 Offline access
 * Users can access the most recent channel they've loaded even without an internet connection.
 * Cache information from the latest channel in local storage in case of connection outages.
 * When the user tries to interact with the website at all in offline mode (e.g. send message, react) they should receive errors.

#### 2.7.2 Fragment based URL routing
 * Users can access different screens using URL fragments:
 	* `/#channel={channelId}` to access the channel screen of the particular channelId
	* `/#profile` to view the authorised user's own profile
	* `/#profile={userId}` to view the profile of the user with the particular userId

_No course assistance will be provided for this component, you should do your own research as to how to implement this._

### 2.8. Bonus Marks (5%)

An extra 5% of the assignment can be attained via bonus marks, meaning a maximum mark of 105/100. Any bonus marks that extend your ass2 mark above 100% will bleed into other assignment marks, but cannot contribute outside of the 75% of the course that is allocated for assignment marks

Your bonus feature(s) can be anything. You just have to think of something that could make your web app stand out in some minor or major way. Simple examples would include just making sure that your user interface and user experience stands out amongst other students, maybe through some user testing.

You could also add extra features, such as some additional frontend form validations - the possibilities are limitless.

If you do implement a bonus feature, describe the feature and its details in `bonus.md` in the root directory of this repository.

## 3. Getting started

### 3.1. The Frontend

Stub code has been provided to help you get started in:
 * `frontend/index.html`
 * `frontend/styles/provided.css`
 * `frontend/src/helpers.js`
 * `frontend/src/main.js`

You can modify or delete this stub code if you choose. It's simply here to potentially provide some help.

To work with your frontend code locally with the web server, you may have to run another web server to serve the frontend's static files.

To do this, run the following command once on your machine:

`$ npm install --global http-server`

Then whenever you want to start your server, run the following in your project's root folder:

`$ npx http-server frontend -p [port]`

Where `[port]` is the port you want to run the server on (e.g. `8080`). Any number is fine.

This will start up a second HTTP server where if you navigate to `http://localhost:8000` (or whatever URL/port it provides) it will run your `index.html` without any CORs issues.

### 3.2. The Backend

You are prohibited from modifying the backend. No work needs to be done on the backend. It's provided to you simply to power your frontend.

The backend server exists in your individual repository. After you clone this repo, you must run `yarn install` in `backend` directory once.

To run the backend server, simply run `yarn start` in the `backend` directory. This will start the backend.

To view the API interface for the backend you can navigate to the base URL of the backend (e.g. `http://localhost:5005`). This will list all of the HTTP routes that you can interact with.

We have provided you with a very basic starting database containing two users and one public channel with messages. You can look in `backend/database.json` to see the contents.

Your backend is persistent in terms of data storage. That means the data will remain even after your express server process stops running. If you want to reset the data in the backend to the original starting state, you can run `yarn reset` in the backend directory. If you want to make a copy of the backend data (e.g. for a backup) then simply copy `database.json`. If you want to start with an empty database, you can run `yarn clear` in the backend directory.

Once the backend has started, you can view the API documentation by navigating to `http://localhost:[port]` in a web browser.

The port that the backend runs on (and that the frontend can use) is specified in `frontend/src/config.js`. You can change the port in this file. This file exists so that your frontend knows what port to use when talking to the backend.

Please note: If you manually update database.json you will need to restart your server.

## 4. Constraints & Assumptions

### 4.1. Javascript

 * You must implement this assignment in ES6-compliant Vanilla JavaScript. You cannot use ReactJS, JQuery, or other abstract frameworks. You can not, for example, use a popular Javascript framework such as <a href="https://angular.io/">Angular</a> or <a href="https://reactjs.org/">React</a>.
 * You may **NOT** directly use external JavaScript. Do not use NPM except to install any other development libraries without prior approval from course authority.

### 4.2. CSS and other libraries

 * You may use small amounts (&lt; 10 lines) of general purpose code (not specific to the assignment) obtained from a site such as Stack Overflow or other publically available resources. You should clearly attribute the source of this code in a comment with it. You can not otherwise use code written by another person.
 * You may include external CSS libraries in this assignment (with the `<link />` tag). You must attribute these sources (i.e. provide the URL/author in source code comments). For example, you are permitted to use the popular <a href="https://getbootstrap.com/">Bootstrap</a> CSS framework. Some Bootstrap functionality relies on accompanying Javascript. You are permitted to include this Javascript. The Javascript accompanying Bootstrap requires the popular general purpose Javascrpt library <a href="https://jquery.com/">jQuery</a>. You are permitted to include <b>jQuery</b> so bootstrap can use it. However you are not permitted to use <b>jQuery</b> in the code you write for the assignment.

### 4.3. Browser Compatibility

You should ensure that your programs have been tested on one of the following two browsers:
 * Locally, Google Chrome (various operating systems)
 * On CSE machines, Chromium

### 4.4. Other Requirements

 * The specification is intentionally vague to allow you to build frontend components however you think are visually appropriate. Their size, positioning, colour, layout, is in virtually all cases completely up to you. We require some basic criteria, but it's mainly dictating elements and behaviour.
 * This is not a design assignment. You are expected to show common sense and critical thinking when it comes to basic user experience and visual layout, but you are not required to be creative to achieve full marks.

### 4.5. Static HTML, innerHTML, DOM manipulation

In this assignment, you are:
 * Allowed to add static HTML/CSS to the stub website provided (i.e. you can put raw HTML/CSS as if it's a static page, even if you then later manipulate it with JavaScript).
 * Allowed to build HTML elements and add CSS properties to the DOM via JavaScript. We expect this to be the most common way students build these pages.
 * Are **not** allowed to use the `innerHTML` property of nodes/tags to set the inner HTML of an element. This has security vulnerabilities and is in general not best practice. Either statically add the HTML/CSS and manipulate it with JavaScript, or generate and build nodes/elements in JavaScript (just like in lectures/tutes/labs), or both. But don't set inner HTML.

### 4.6. Async, Await, Promises

You are prohibited from using the `async` and `await` syntax in this assignment. You must use ES6 Promises.

## 5. Marking Criteria

Your assignment will be hand-marked by tutor(s) in the course according to the criteria below.

<table>
	<tr>
		<th>Criteria</th>
		<th>Weighting</th>
		<th>Description</th>
	</tr>
	<tr>
		<td>Compliance to task requirements</td>
		<td>70%</td>
		<td>
			<ul>
				<li>Each milestone specified a particular % of overall assignment (summing up to 70%). Implement those components as required to receive the marks.</li>
			</ul>
		</td>
	</tr>
	<tr>
		<td>Mobile Responsiveness</td>
		<td>15%</td>
		<td>
			<ul>
				<li>Your application is usable for desktop sizes generally, tablet sizes generally, and mobile sizes generally (down to 400px wide, 700px high).</li>
			</ul>
		</td>
	</tr>
	<tr>
		<td>Code Style</td>
		<td>10%</td>
		<td>
			<ul>
				<li>Your code is clean, well commented, with well-named variables, and is well laid out.</li>
			</ul>
		</td>
	</tr>
	<tr>
		<td>Usability & Accessibility</td>
		<td>5%</td>
		<td>
			<ul>
				<li>Your application is usable and easy to navigate. No obvious usability issues or confusing layouts/flows.</li>
				<li>Your application follows standard accessibility guidelines, such as use of alt tags, and colours that aren't inaccessible.</li>
			</ul>
		</td>
	</tr>
</table>

## 6. Originality of Work

The work you submit must be your own work. Submission of work partially or completely derived from
any other person or jointly written with any other person is not permitted.

The penalties for such an offence may include negative marks, automatic failure of the course and
possibly other academic discipline. Assignment submissions will be examined both automatically and
manually for such submissions.

Relevant scholarship authorities will be informed if students holding scholarships are involved in
an incident of plagiarism or other misconduct.

Do not provide or show your assignment work to any other person &mdash; apart from the teaching
staff of COMP6080.

If you knowingly provide or show your assignment work to another person for any reason, and work
derived from it is submitted, you may be penalized, even if the work was submitted without your
knowledge or consent.  This may apply even if your work is submitted by a third party unknown to
you.

Every time you make commits or pushes on this repository, you are acknowledging that the work you
submit is your own work (as described above).

Note you will not be penalized if your work has the potential to be taken without your consent or
knowledge.

## 7. Submission

This assignment is due *Monday 24th of October, 10pm*.

To submit your assignment, simply run the following command on a CSE terminal:

`$ 6080 submit ass2`

This will submit the latest commit on master as your submission.

It is your responsibiltiy to ensure that your code can be successfully demonstrated on the CSE machines (e.g. vlab)
from a fresh clone of your repository. Failure to ensure this may result in a loss of marks.

## 8. Late Submission Policy

If your assignment is submitted after this date, each hour it is late reduces the maximum mark it can achieve by 2%.

For example, if an assignment you submitted with a raw awarded mark of 85% was submitted 5 hours late, the late submission would have no effect (as maximum mark would be 90%). If the same assignment was submitted 20 hours late it would be awarded 60%, the maximum mark it can achieve at that time.
