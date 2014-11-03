#include <stdio.h>
#include <cv.h>
#include <highgui.h>
#include "video.h"
#include "rtspd.h"

void openVideo(RTSPClient* clientInfo, char* file_path)
{
	// Open the video file.
	if (clientInfo->video == NULL)
	{
			clientInfo->video = cvCreateFileCapture(msg.file_path);
	}
	else
	{
			clientInfo->video = cvCaptureFromFile(msg.file_path);
	}
//TODO: handle when video is already open/playing
	if (!video) {
		printf("could not open video %s\n", file_path);
	}
}

IplImage* nextFrame(CvCapture* video)
{
	IplImage* image;
	image = cvQueryFrame(video);
	if (!image) {
		printf("could not get frame\n");
		return NULL;	  // The file doesn't exist or can't be captured as a video file.
	}
	return image;
}

void setFrameIdx(CvCapture *video, int i){
	// Change current position of the video so that the next call to cvQueryFrame
	// will return the i'th frame.
	cvSetCaptureProperty(video, CV_CAP_PROP_POS_FRAMES, i);

}
