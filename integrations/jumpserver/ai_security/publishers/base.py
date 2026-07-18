from abc import ABC, abstractmethod


class BasePublisher(ABC):
    @abstractmethod
    def publish(self, events):
        raise NotImplementedError
