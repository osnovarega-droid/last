from Managers.GSIManager import GSIManager
from Managers.VideoConfigManager import VideoConfigManager
from ui.app import App

if __name__ == "__main__":
    video_config_manager = VideoConfigManager()
    startup_gpu_info = video_config_manager.sync_on_startup()

    gsi = GSIManager()
    gsi.start()


    app = App(gsi_manager=gsi, startup_gpu_info=startup_gpu_info)
    app.mainloop()