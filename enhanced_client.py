import asyncio
import websockets
import json
import pyaudio
import pygame
import numpy as np
import time
import uuid
from audio_utils import AudioProcessor, CHUNK_SIZE, FORMAT, CHANNELS, RATE
from virtual_instruments import VirtualGuitar, VirtualKeyboard
from ui_components import Button, Slider, Vis